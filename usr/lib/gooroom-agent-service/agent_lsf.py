#!/usr/bin/env python3

#-----------------------------------------------------------------------
import ctypes
import os

from agent_util import AgentConfig, AgentLog, agent_format_exc
from agent_define import *

#-----------------------------------------------------------------------
class LSF_USER_DATA_T(ctypes.Structure):
    _fields_ = [('symm_key', ctypes.c_char * 1024),
                ('access_token', ctypes.c_char * 1024),
                ('dbus_name', ctypes.c_char * 256),
                ('password', ctypes.c_char * 256),
                ('absolute_path', ctypes.c_char * 4096),
                ('auth_type', ctypes.c_int)]

#-----------------------------------------------------------------------
def get_api():
    """
    get liblsf.so instance
    """

    if not get_api.api:
        get_api.api = ctypes.CDLL(LSF_LIB_PATH)
    return get_api.api

get_api.api = None

#-----------------------------------------------------------------------
def lsf_interlock():
    """
    check if gooroom security framework is on
    """

    if not os.path.exists(LSF_INTERLOCK_PATH):
        return False

    lsf_conf = AgentConfig.get_config(LSF_INTERLOCK_PATH, reload=True)
    v = lsf_conf.get(LSF_INTERLOCK_SECTION, LSF_INTERLOCK_KEY)
    if v.lower() == LSF_INTERLOCK_ON:
        return True
    else:
        return False
        
#-----------------------------------------------------------------------
def lsf_auth(data_center):
    """
    auth to lsf
    """

    try:
        api = get_api()
        udata = LSF_USER_DATA_T()
        r = api.lsf_auth(ctypes.pointer(udata), LSF_PHRASE.encode('utf-8'))
        if r == 0:
            data_center.lsf_symm_key = udata.symm_key
            data_center.lsf_access_token = udata.access_token
            AgentLog.get_logger().info('AUTH SUCCESS')
            AgentLog.get_logger().debug('symm={} token={}'.format(
                                                        udata.symm_key, 
                                                        udata.access_token))
        else:
            AgentLog.get_logger().info('AUTH FAILURE:{}'.format(r))
        return r
    except:
        AgentLog.get_logger().error(agent_format_exc())
        return -1;

#-----------------------------------------------------------------------
def lsf_dec_msg(data_center, msg):
    """
    decrypt aes message from lsf
    """

    return lsf_decode_base64_and_decrypt_aes(
                                    msg.encode('utf-8'), 
                                    data_center.symm_key.encode('utf-8'))

#-----------------------------------------------------------------------
def lsf_send_msg(data_center, msg):
    """
    send message to lsf
    """

    if not lsf_interlock():
        return None

    if not data_center.symm_key:
        if lsf_auth(data_center) != 0:
            return None

    resp = ctypes.POINTER(ctypes.c_char)()
    api = get_api()
    api.lsf_send_message(
                        data_center.symm_key.encode('utf-8'), 
                        msg.encode('utf-8'), 
                        ctypes.byref(resp))
    return resp

