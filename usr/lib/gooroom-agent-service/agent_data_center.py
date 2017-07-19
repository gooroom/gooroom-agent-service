#! /usr/bin/env python3

#-----------------------------------------------------------------------
import simplejson as json
import threading
import importlib
import httplib2
import OpenSSL
import ctypes
import queue
import glob
import sys
import re

from agent_util import AgentConfig,AgentLog
from agent_simple_parser import SimpleParser
from agent_msslrest import AgentMsslRest
from agent_define import *

#-----------------------------------------------------------------------
class AgentDataCenter:
	"""
	DATA CENTER
	"""

	def __init__(self):

		self.conf = AgentConfig.get_config(reload=True)
		self.logger = AgentLog.get_logger()

		self.center_lock = threading.Lock()

		self.show(once=True)

	def show(self, once=False):
		"""
		show 
		"""

		self.center_lock.acquire()

		try:
			self.logger.info('BEGIN SHOW()')

			if once:
				#DISPATCHERS CONTROLL FLAG
				#client_dispatcher와 server_dispatcher는 이 플래그값을 가지고
				#서로의 looping을 제어한다.
				#client_dispatcher가 초기화작업이 완료되면 serverjob의
				#looping을 True로 변경한다.
				#server_dispatcher가 서버와의 통신에 장애가 발생하면 
				#clinetjob의 looping을 False로 변경하고 
				#통신이 정상화되면 다시 looping을 True로 변경한다.
				self.serverjob_looping_on = [False]
				self.clientjob_looping_on = [True]

			#CLIENT ID
			self.client_id = self.extract_clientid_from_cert()
		
			#SERVER DOMAIN
			self.server_domain = self.read_server_domain()

			#SERVERJOB DISPATCHER VARIABLES
			self.jobs_api = self.conf.get('REST_API', 'JOBS')
			self.server_api = self.conf.get('REST_API', 'SERVER')
			self.serverjob_dispatch_time = self.get_serverjob_dispatch_time()

			#CLIENTJOB DISPATCHER VARIABLES
			self.client_api = self.conf.get('REST_API', 'CLIENT')

			#WORKER
			self.Q_max_size = int(self.conf.get('WORKER', 'MAX_Q_SIZE'))
			self.serverjob_Q = queue.Queue(self.Q_max_size)
			self.clientjob_Q = queue.Queue(self.Q_max_size)
			self.job_num_per_worker = int(self.conf.get('WORKER', 'JOB_NUM_PER_WORKER'))
			self.job_max_worker_num = int(self.conf.get('WORKER', 'MAX_WORKER_NUM'))
			self.worker_lifetime = int(self.conf.get('WORKER', 'WORKER_LIFETIME'))

			#XML PARSER FOR MODULE TEMPLATES
			self.parser = SimpleParser(
				self.conf.get('MAIN', 'MODULE_TMPL_PATH'), 
				self.conf.get('MAIN', 'MODULE_TMPL_NAMESPACE')
				) 

			#CLIENTJOB BOOK
			#모듈템플릿에서 polltime 값이 동일한 task들을 하나의 JOB으로
			#생성해서 { polltime:JOB } 으로 매핑
			self.clientjob_book = self.parser.clientjob_book()

			#BOOTABLE TASK LIST
			self.bootable_tasks = self.parser.bootable_tasks()

			#LOAD MODULE TEMPLATES
			self.load_modules()

			#M-SSL
			self.agent_cert = self.conf.get('MAIN', 'AGENT_CERT')
			self.agent_key = self.conf.get('MAIN', 'AGENT_KEY')
			self.agent_ca_cert = self.conf.get('MAIN', 'AGENT_CA_CERT')

			self.auth_api = self.conf.get('REST_API', 'AUTH_TOKEN')
			self.rest_timeout = float(self.conf.get('MAIN', 'REST_TIMEOUT'))

			self.agent_http = httplib2.Http(timeout=self.rest_timeout)
			self.agent_http = httplib2.Http(ca_certs=self.agent_ca_cert, timeout=self.rest_timeout)
			self.agent_http.add_certificate(key=self.agent_key, cert=self.agent_cert, domain='')

			#MUTUAL SSL RESTFUL
			self.restful = AgentMsslRest(self)# self.client_id, self.server_domain, self.auth_api, self.agent_http)

			self.logger.info('END SHOW()')

		except:
			raise

		finally:
			self.center_lock.release()

	def module_request(self, task, job_no=-1, mustbedata=True, remove_request=True):
		"""
		restful.request wrapper for module
		"""

		agent_data = self.create_agentdata(job_no, self.client_id, [task])
		server_rsp, status_code, err_msg = self.restful.request(self.client_api,
			body=json.dumps({J_AGENT_DATA:agent_data}))

		if remove_request and J_REQUEST in task[J_MOD][J_TASK]:
			task[J_MOD][J_TASK].pop(J_REQUEST)

		if status_code != AGENT_OK:
			raise Exception('code=%s err_msg=%s' % (status_code, err_msg))
		if mustbedata:
			if len(server_rsp) <= 0:
				raise Exception('agent-data empty')
			else:
				return json.loads(server_rsp[0][J_OB])
		else:
			return server_rsp

	def clientjob_request(self, task, job_no=-1):
		"""
		restful.request wrapper for clientjob worker
		"""

		agent_data = self.create_agentdata(job_no, self.client_id, [task])
		return self.restful.request(self.client_api,
			body=json.dumps({J_AGENT_DATA:agent_data}))

	def serverjob_request(self, task_list, job_no):
		"""
		restful.request wrapper for serverjob worker
		"""

		agent_status, agent_data = \
			self.create_agentbody('', AGENT_OK, '', job_no, self.client_id, task_list)

		return self.restful.request(self.server_api,
			body=json.dumps({J_AGENT_STATUS:agent_status, J_AGENT_DATA:agent_data}))

	def jobs_request(self):
		"""
		restful.request wrapper for jobs
		"""

		return self.restful.request(self.jobs_api, method='GET')

	def create_agentbody(self, agent, code, err, job_no, client_id, module_rsp):
		"""
		create agent body(agent status + agent data)
		"""

		agent_status = {}
		agent_data = [{}]

		agent_status[J_AGENT_STATUS_RESULT] = agent
		agent_status[J_AGENT_STATUS_RESULTCODE] = code
		agent_status[J_AGENT_STATUS_MESSAGE] = err

		agent_data = self.create_agentdata(job_no, client_id, module_rsp)

		return agent_status, agent_data

	def create_agentdata(self, job_no, client_id, module_rsp):
		"""
		create agent data
		"""

		agent_data = [{}]

		agent_data[0][J_AGENT_DATA_JOBNO] = job_no
		agent_data[0][J_AGENT_DATA_CLIENTID] = client_id
		agent_data[0][J_AGENT_DATA_JOBDATA] = json.dumps(module_rsp)

		return agent_data

	def get_serverjob_dispatch_time(self):
		"""
		get dispatch time from config
		"""

		dt = float(self.conf.get(SERVERJOB, 'DISPATCH_TIME'))
		if (dt < 3.0):
			self.logger.error('!! (serverjob) invalid dispatch_time=%f.\
				replace it from default value' % self.dispatch_time)
			dt = 3.0

		return dt

	def extract_clientid_from_cert(self):
		"""
		get clientid from certificate
		"""

		cert_path = self.conf.get('MAIN', 'AGENT_CERT')
		cert = None

		with open(cert_path) as f:
			cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, f.read())

		if cert:
			cn = cert.get_subject().CN
			self.logger.info('client_id=%s', cn)
			return cn
		else:
			return None

	def read_server_domain(self):
		"""
		return server domain 
		"""

		path = self.conf.get('MAIN', 'AGENT_SERVER_DOMAIN_PATH')
		section = self.conf.get('MAIN', 'AGENT_SERVER_DOMAIN_SECTION')
		key = self.conf.get('MAIN', 'AGENT_SERVER_DOMAIN_KEY')

		server_domain = AgentConfig.get_config(path, reload=True).get(section, key)
		self.logger.info('server_domain=%s', server_domain)
		return server_domain

	def load_modules(self):
		"""
		설정파일에 있는 모듈(플러그인) 디렉토리에 있는 
		모든 모듈을 로드
		"""

		#{패키지명:모듈객체}
		self.modules = {}

		module_path = self.conf.get('MAIN', 'MODULE_PATH')
		if module_path[-1] != '/':
			module_path += '/'

		#PYTHONPATH에 모듈디렉토리경로 추가
		sys.path.append(module_path)

		self._load_python_modules(module_path)
		self._load_c_modules(module_path)

	def _load_c_modules(self, module_path):
		"""
		.SO 에서 C모듈 로드
		"""

		module_fullpath = '%s*.so' % module_path

		for module_fullname in glob.glob(module_fullpath):
			module_name = module_fullname.split('/')[-1].split('.')[0]

			if module_name in self.modules:
				continue

			lib = ctypes.cdll.LoadLibrary(module_fullname)
			lib.do_job.argtypes = (ctypes.c_char_p,)
			lib.do_job.restype = ctypes.POINTER(ctypes.c_char)

			self.modules[module_name] = lib
			self.logger.debug('(c) %s(%s) loaded' % (module_name, module_fullname))

		self._libc = ctypes.CDLL(ctypes.util.find_library('c'))

	def _load_python_modules(self, module_path):
		"""
		파이썬 모듈 로드
		"""

		module_fullpath = '%s*' % module_path

		py_ext = re.compile('.*[.py|.pyc]$')

		for module_fullname in (f for f in glob.glob(module_fullpath) if py_ext.match(f)):
			module_name = module_fullname.split('/')[-1].split('.')[0]

			if module_name in self.modules:
				continue

			self.modules[module_name] = importlib.import_module(module_name)
			self.logger.debug('(py) %s(%s) loaded' % (module_name, module_fullname))

