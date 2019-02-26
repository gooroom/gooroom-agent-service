#! /usr/bin/env python3

#-----------------------------------------------------------------------
import simplejson as json
import base64
import pwd
import os

from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

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
        uid = pwd.getpwnam(login_id).pw_uid
        grm_user_path = '/var/run/user/{}/gooroom/.grm-user'.format(uid)
        with open(grm_user_path) as f:
            gu = json.loads(f.read())
            session_id = gu['data']['loginInfo']['login_token']

    key_path = AgentConfig.get_config().get('MAIN', 'AGENT_KEY')
    with open(key_path) as f:
        private_key = RSA.importKey(f.read())

    signer = PKCS1_v1_5.new(private_key)
    digest = SHA256.new()
    msg = '{}&{}'.format(client_id, session_id)
    digest.update(msg.encode('utf8'))
    signing = base64.b64encode(signer.sign(digest)).decode('utf8')

    return signing, session_id

def task_get_noti(task, data_center):
    """
    get noti
    """

    login_id = task[J_MOD][J_TASK][J_IN]['login_id']
    with open('/etc/passwd') as f:
        pws = f.readlines()
    for pw in pws:
        splited = pw.split(':')
        if splited[0] == login_id:
            if not 'gooroom-online-account' in splited[4]:
                login_id = ''
            break
    else:
        raise Exception('no user in /etc/passwd')

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

