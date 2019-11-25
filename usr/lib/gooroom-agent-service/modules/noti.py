#! /usr/bin/env python3

#-----------------------------------------------------------------------
import simplejson as json
import base64
import pwd
import os

from OpenSSL import crypto
import OpenSSL

from agent_util import AgentConfig,AgentLog,agent_format_exc,catch_user_id
from agent_define import *

#-----------------------------------------------------------------------
def do_task(task, data_center):
    """
    do task
    """

    task[J_MOD][J_TASK][J_OUT] = \
        {J_STATUS : AGENT_OK, J_MESSAGE : AGENT_DEFAULT_MESSAGE}

    try:
        eval('task_%s(task, data_center)' % task[J_MOD][J_TASK][J_TASKN])

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

#------------------------------------------------------------------------
def get_signing_and_session_id(client_id, login_id):
    """
    get sigining and session_id
    """

    session_id = ''
    if login_id:
        grm_user_path = '/home/{}/.gooroom/.grm-user'.format(login_id)
        with open(grm_user_path) as f:
            gu = json.loads(f.read())
            session_id = gu['data']['loginInfo']['login_token']

    key_path = AgentConfig.get_config().get('MAIN', 'AGENT_KEY')
    with open(key_path) as f:
        private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read(), None)

    msg = '{}&{}'.format(client_id, session_id)
    signing = base64.b64encode(OpenSSL.crypto.sign(private_key, msg, 'sha256'))

    return signing, session_id

def task_get_noti(task, data_center):
    """
    get noti
    """

    login_id = catch_user_id()
    if login_id == '-' or login_id[0] == '+':
        login_id = ''

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {'login_id':login_id}
    server_rsp = data_center.module_request(task)
    noti_info = server_rsp[J_MOD][J_TASK][J_RESPONSE]['noti_info']
    client_id = noti_info['client_id']
    signing, session_id = get_signing_and_session_id(client_id, login_id)
    noti_info['session_id'] = session_id
    noti_info['signing'] = signing
    task[J_MOD][J_TASK][J_OUT]['noti_info'] = noti_info

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_set_noti(task, data_center):
    """
    set noti
    """

    login_id = catch_user_id()
    if login_id == '-' or login_id[0] == '+':
        login_id = ''

    notice_publish_id = task[J_MOD][J_TASK][J_IN]['notice_publish_id']

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {'login_id':login_id}
    task[J_MOD][J_TASK][J_REQUEST]['notice_publish_id'] = notice_publish_id
    server_rsp = data_center.module_request(task)
    noti_info = server_rsp[J_MOD][J_TASK][J_RESPONSE]['noti_info']
    client_id = data_center.get_client_id()
    noti_info['client_id'] = client_id
    signing, session_id = get_signing_and_session_id(client_id, login_id)
    noti_info['session_id'] = session_id
    noti_info['signing'] = signing
    data_center.GOOROOM_AGENT.set_noti(json.dumps(noti_info))

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_set_multiple_login_msg(task, data_center):
    """
    set multiple login msg
    """
    login_id = catch_user_id()
    if login_id == '-' or login_id[0] == '+':
        raise Exception('current login-id({}) is not gpms-id'.format(login_id))

    gpms_id = task[J_MOD][J_TASK][J_IN]['login_id']
    if gpms_id != login_id:
        raise Exception('gpms-id({}) and login-id({}) is not equal'.format(
                                                                    gpms_id,
                                                                    login_id))
    '''
    msg = '{}:{}'.format(
        GRMCODE_NO_JOURNAL_DEFAULT, 
        task[J_MOD][J_TASK][J_IN]['msg'])
    '''
    msg = '다른 장치에서 접속을 시도했습니다'

    task[J_MOD][J_TASK].pop(J_IN)

    data_center.GOOROOM_AGENT.agent_msg(msg)

