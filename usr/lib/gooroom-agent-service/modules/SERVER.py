#! /usr/bin/env python3

#-----------------------------------------------------------------------
from agent_util import AgentConfig,AgentLog,agent_format_exc
from agent_define import *

#-----------------------------------------------------------------------
def do_task(task, data_center):
    """
    do task
    """

    task[J_MOD][J_TASK][J_OUT] = \
        {J_STATUS : AGENT_OK, J_MESSAGE : AGENT_DEFAULT_MESSAGE}

    try:
        task_name = task[J_MOD][J_TASK][J_TASKN]
        task_func = globals().get('task_%s' % task_name) \
            if isinstance(task_name, str) and task_name.isidentifier() else None
        if not callable(task_func):
            raise Exception('invalid task name: %r' % (task_name,))
        task_func(task, data_center)

    except:
        task[J_MOD][J_TASK][J_OUT][J_STATUS] = AGENT_NOK
        e = agent_format_exc()
        task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = e

        AgentLog.get_logger().error(e)

    if J_IN in task[J_MOD][J_TASK]:
        task[J_MOD][J_TASK].pop(J_IN)
    if J_REQUEST in task[J_MOD][J_TASK]:
        task[J_MOD][J_TASK].pop(J_REQUEST)
    if J_RESPONSE in task[J_MOD][J_TASK]:
        task[J_MOD][J_TASK].pop(J_RESPONSE)

    return task

#-----------------------------------------------------------------------
def task_grm_heartbit(task, data_center):
    """
    do do_task
    """

    task[J_MOD][J_TASK].pop(J_IN)
    if data_center.agent_grm_connection_status[0]:
        task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST
    else:
        task[J_MOD][J_TASK][J_OUT][J_STATUS] = AGENT_NOK
        task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = \
            'agent is failing to connect to server'
    
