#! /usr/bin/env python3

#-----------------------------------------------------------------------
import subprocess
import importlib
import traceback
import sys
import os

from agent_util import AgentConfig, AgentLog
from agent_define import *
from systemd import journal

#----------------------------------------------------------------------- 
def do_task(task, data_center):
	"""
	do task
	"""

	task[J_MOD][J_TASK][J_OUT] = {J_STATUS : AGENT_OK, J_ERR_REASON : ''}

	try:
		eval('task_%s(task, data_center)' % task[J_MOD][J_TASK][J_TASKN])

	except:
		task[J_MOD][J_TASK][J_OUT][J_STATUS] = AGENT_NOK
		e = traceback.format_exc()
		task[J_MOD][J_TASK][J_OUT][J_ERR_REASON] = e

		AgentLog.get_logger().error(e)

	if J_IN in task[J_MOD][J_TASK]:
		task[J_MOD][J_TASK].pop(J_IN)
	if J_REQUEST in task[J_MOD][J_TASK]:
		task[J_MOD][J_TASK].pop(J_REQUEST)
	if J_RESPONSE in task[J_MOD][J_TASK]:
		task[J_MOD][J_TASK].pop(J_RESPONSE)

	return task

#-----------------------------------------------------------------------
def task_summary_log(task, data_center):
	"""
	summary_log
	"""

	motherboard_serial = read_boardserial()
	os_ver = read_os()
	kernel = read_kernel()
	ip = read_ip()
	
	task[J_MOD][J_TASK][J_OUT]['terminal_info'] = \
		'%s,%s,%s,%s' % (motherboard_serial, os_ver, kernel, ip)
	
	load_security_log(task)

	task[J_MOD][J_TASK][J_OUT]['safe_score'] = '0'
	user_id = os.getenv('USER')
	if not user_id:
		user_id = 'system'

	task[J_MOD][J_TASK][J_OUT]['user_id'] = user_id

#-----------------------------------------------------------------------
def read_last_seek_time(backup_path):
	"""
	read last seek time from file
	"""

	fullpath = backup_path+'security_last_seek_time'

	if not os.path.exists(fullpath):
		return None

	t = None
	with open(fullpath) as f:
		t = f.readline().strip().rstrip('\n')

	return float(t)

#-----------------------------------------------------------------------
def write_last_seek_time(backup_path, next_seek_time):
	"""
	write last seek time to file
	"""

	if not os.path.isdir(backup_path):
		os.makedirs(backup_path)

	with open(backup_path+'security_last_seek_time', 'w') as f:
		f.write(str(next_seek_time))


#-----------------------------------------------------------------------
def load_security_log(task):
	"""
	load security log on journal
	"""

	backup_path = AgentConfig.get_config().get('MAIN', 'AGENT_BACKUP_PATH')
	if backup_path[-1] != '/':
		backup_path += '/'

	j = journal.Reader()

	#이전 작업시간을 저장하고 있는 파일을 읽어서
	last_seek_time = read_last_seek_time(backup_path)

	#시간이 있으면 이전 작업시간+.000001초 부터 검색
	#journal이 마이크로초까지 저장
	if last_seek_time:
		j.seek_realtime(last_seek_time+.000001)

	#파일이 없거나 시간이 없으면 부팅 이후 부터 검색
	else:
		pass
	
	logs = []

	for entry in j:
		#tuple로 교체 제안
		#logs.append((entry['__REALTIME_TIMESTAMP'], entry['_TRANSPORT'], entry['MESSAGE']))
		logs.append({"timestamp": entry["__REALTIME_TIMESTAMP"], 
			"daemon" : entry["_TRANSPORT"], 
			"message" : entry["MESSAGE"]})

		last_seek_time = entry['__REALTIME_TIMESTAMP'].timestamp()

	#load modules
	module_path = AgentConfig.get_config().get('SECURITY', 'SECURITY_MODULE_PATH')
	sys.path.append(module_path)
	#invoke get_summary
	for sf in ('os', 'exe', 'boot', 'media'):
		m = importlib.import_module('security.'+sf)
		status, log = getattr(m, 'get_summary')(logs)

		if not log:
			continue

		task[J_MOD][J_TASK][J_OUT][sf+'_status'] = status
		task[J_MOD][J_TASK][J_OUT][sf+'_log'] = '\n'.join(log)
		
	#save lask seek_time to file
	write_last_seek_time(backup_path, last_seek_time)

#-----------------------------------------------------------------------
def read_boardserial():
	"""
	return motherboard serial number
	"""

	with open('/sys/devices/virtual/dmi/id/product_uuid') as f:
		return f.read().split('\n')[0]

#-----------------------------------------------------------------------
def read_kernel():
	"""
	return kernel version
	"""

	with open('/proc/sys/kernel/version') as f:
		return f.read().split('\n')[0]

#-----------------------------------------------------------------------
def read_os():
	"""
	return os version
	"""

	with open('/etc/lsb-release') as f:
		lines = f.read().rstrip('\n').split('\n')
		info = {}
		for line in lines:
			k,v = line.split('=')
			info[k] = v

		return '%s %s %s' % (
			info['DISTRIB_ID'], 
			info['DISTRIB_CODENAME'], 
			info['DISTRIB_RELEASE'])

#-----------------------------------------------------------------------
def read_ip():
	"""
	return ip address
	"""
	
	#should modify to read ip from file
	ip = subprocess.check_output('hostname -I'.split()).decode('utf8').rstrip('\n')
	return ip

