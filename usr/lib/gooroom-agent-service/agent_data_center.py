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
import ssl
import sys
import re

from agent_util import AgentConfig,AgentLog,catch_user_id
from agent_simple_parser import SimpleParser
from agent_msslrest import AgentMsslRest
from agent_define import *

#-----------------------------------------------------------------------
class AgentDataCenter:
    """
    DATA CENTER
    """

    def __init__(self, gooroom_agent):

        self.GOOROOM_AGENT = gooroom_agent

        self.conf = AgentConfig.get_config()
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
            #self.client_id = self.extract_clientid_from_cert()
        
            #SERVER DOMAIN
            self.server_domain = self.read_server_domain()

            #SERVERJOB DISPATCHER VARIABLES
            self.jobs_api = self.conf.get('REST_API', 'JOBS')
            self.server_api = self.conf.get('REST_API', 'SERVER')
            self.serverjob_dispatch_time = self.get_serverjob_dispatch_time()
            self.serverjob_max_dispatch_time = int(self.conf.get('SERVERJOB', 'MAX_DISPATCH_TIME'))

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

            #DBUS ALLOWED TASKS
            self.dbusable_tasks = self.parser.dbusable_tasks()

            #LOAD MODULE TEMPLATES
            self.load_modules()

            #M-SSL
            self.agent_cert = self.conf.get('MAIN', 'AGENT_CERT')
            self.agent_key = self.conf.get('MAIN', 'AGENT_KEY')
            self.agent_ca_cert = self.conf.get('MAIN', 'AGENT_CA_CERT')

            self.auth_api = self.conf.get('REST_API', 'AUTH_TOKEN')
            self.rest_timeout = float(self.conf.get('MAIN', 'REST_TIMEOUT'))

            self.agent_http = httplib2.Http(ca_certs=self.agent_ca_cert, timeout=self.rest_timeout)
            self.agent_http.add_certificate(key=self.agent_key, cert=self.agent_cert, domain='')

            #MUTUAL SSL RESTFUL
            self.restful = AgentMsslRest(self)

            #JOURNAL LOG LEVEL
            self.journal_loglevel = int(self.conf.get('SECURITY', 'JOURNAL_LOGLEVEL'))

            #PACKAGE OPERATION
            self.package_operation = self.conf.get('MAIN', 'PACKAGE_OPERATION')

            self.logger.info('END SHOW()')

        except:
            raise

        finally:
            self.center_lock.release()

    def create_httplib2_http(self):
        """
        return new httplib2.Http
        """
        
        new_http = httplib2.Http(ca_certs=self.agent_ca_cert, timeout=self.rest_timeout)
        new_http.add_certificate(key=self.agent_key, cert=self.agent_cert, domain='')
        return new_http
        
    def module_request(self, task, job_no=-1, mustbedata=True, remove_request=True):
        """
        restful.request wrapper for module
        """

        agent_data = self.create_agentdata(job_no, [task])
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

        agent_data = self.create_agentdata(job_no, [task])
        return self.restful.request(self.client_api,
            body=json.dumps({J_AGENT_DATA:agent_data}))

    def serverjob_request(self, task_list, job_no, job_status):
        """
        restful.request wrapper for serverjob worker
        """

        agent_status, agent_data = \
            self.create_agentbody('', job_status, '', job_no, task_list)

        return self.restful.request(self.server_api,
            body=json.dumps({J_AGENT_STATUS:agent_status, J_AGENT_DATA:agent_data}))

    def jobs_request(self):
        """
        restful.request wrapper for jobs
        """

        user_id = None
        try:
            user_id = catch_user_id()
        except:
            user_id = '***TERMINAL ERROR***'
            raise

        b = {'client_id':self.get_client_id(), 'user_id':user_id, 'type:':0}
        return self.restful.request(
            self.jobs_api, body=json.dumps(b))

    def create_agentbody(self, agent, code, err, job_no, module_rsp):
        """
        create agent body(agent status + agent data)
        """

        agent_status = {}
        agent_data = [{}]

        agent_status[J_AGENT_STATUS_RESULT] = agent
        agent_status[J_AGENT_STATUS_RESULTCODE] = code
        agent_status[J_AGENT_STATUS_MESSAGE] = err

        agent_data = self.create_agentdata(job_no, module_rsp)

        return agent_status, agent_data

    def create_agentdata(self, job_no, module_rsp):
        """
        create agent data
        """

        agent_data = [{}]

        agent_data[0][J_AGENT_DATA_JOBNO] = job_no
        agent_data[0][J_AGENT_DATA_CLIENTID] = self.get_client_id()
        agent_data[0][J_AGENT_DATA_JOBDATA] = json.dumps(module_rsp)

        return agent_data

    def set_package_operation(self, operation):
        """
        set package operation
        """

        old_t = self.package_operation
        new_t = self.package_operation = operation
        self.logger.info(
            'package operation %s -> %s' % (old_t, new_t))

    def reload_serverjob_dispatch_time(self):
        """
        reload dispatch time from config
        """

        old_t = self.serverjob_dispatch_time
        new_t = self.serverjob_dispatch_time = self.get_serverjob_dispatch_time()
        self.logger.info(
            'reloaded serverjob_dispatch_time %d -> %d' % (old_t, new_t))

    def get_serverjob_dispatch_time(self):
        """
        get dispatch time from config
        """

        min_dt = 5.0
        dt = None
        try:
            dt = float(self.conf.get(SERVERJOB, 'DISPATCH_TIME'))
            if (dt < min_dt):
                self.logger.error('!! invalid dispatch_time=%f.\
                    replace it from default value' % self.dispatch_time)
                dt = min_dt
        except Exception as e:
            self.logger.error(e)
            dt = min_dt

        return dt

    def get_client_id(self):
        """
        return clientid
        """

        return self.extract_clientid_from_cert()


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
            self.logger.debug('client_id=%s', cn)
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

