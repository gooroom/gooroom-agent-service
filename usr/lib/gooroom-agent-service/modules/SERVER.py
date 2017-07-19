#! /usr/bin/env python3

#-----------------------------------------------------------------------
import traceback

from agent_util import AgentConfig, AgentLog
from agent_define import *

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

	return task

#-----------------------------------------------------------------------
def task_grm_heartbit(task, data_center):
	"""
	do do_task
	"""

	pass
	
