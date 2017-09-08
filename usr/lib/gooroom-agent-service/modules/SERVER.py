#! /usr/bin/env python3

#-----------------------------------------------------------------------
from agent_util import AgentConfig,AgentLog,agent_format_exc
from agent_define import *

#-----------------------------------------------------------------------
def do_task(task, data_center):
    """
    do task
    """

    task[J_MOD][J_TASK][J_OUT] = {J_STATUS : AGENT_OK, J_MESSAGE : ''}

    try:
        eval('task_%s(task, data_center)' % task[J_MOD][J_TASK][J_TASKN])

    except:
        task[J_MOD][J_TASK][J_OUT][J_STATUS] = AGENT_NOK
        e = agent_format_exc()
        task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = e

        AgentLog.get_logger().error(e)

    return task

#-----------------------------------------------------------------------
def task_grm_heartbit(task, data_center):
    """
    do do_task
    """

    pass
    
#-----------------------------------------------------------------------
def task_get_serverjob_dispatch_time(task, data_center):
    """
    get_serverjob_dispatch_time
    """

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {}

    server_rsp = data_center.module_request(task)
    dispatch_time = server_rsp[J_MOD][J_TASK][J_RESPONSE]['dispatch_time']

    config = AgentConfig.get_config()
    config.set('SERVERJOB', 'DISPATCH_TIME', dispatch_time)

    with open(CONFIG_FULLPATH, 'w') as f:
        config.write(f)

    data_center.reload_serverjob_dispatch_time()

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST


