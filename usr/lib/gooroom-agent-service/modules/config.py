#! /usr/bin/env python3

#-----------------------------------------------------------------------
import xml.etree.ElementTree as etree 
import simplejson as json
import configparser
import subprocess
import importlib
import httplib2
import datetime
import shutil
import ctypes
import gnupg
import stat
import glob
import dbus
import pwd
import sys
import os
import re

from multiprocessing import Process
from pwd import getpwnam
import difflib
import socket

from agent_util import pkcon_exec,verify_signature,send_journallog,apt_exec
from agent_util import AgentConfig,AgentLog,agent_format_exc,catch_user_id
from agent_util import shell_cmd,JLOG
from agent_modfunc import *
from agent_define import *
from agent_lsf import *

#-----------------------------------------------------------------------
def do_task(task, data_center):
    """
    do task
    """

    task[J_MOD][J_TASK][J_OUT] = \
        {J_STATUS : AGENT_OK, J_MESSAGE : AGENT_DEFAULT_MESSAGE}

    try:
        eval('task_%s(task,data_center)' % task[J_MOD][J_TASK][J_TASKN])

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
def task_set_cleanmode_config(task, data_center):
    """
    set cleanmode config
    """

    clean_mode = task[J_MOD][J_TASK][J_IN]['cleanmode_use']
    config = AgentConfig.get_config()
    config.set('CLIENTJOB', 'CLEAN_MODE', clean_mode)
    with open(CONFIG_FULLPATH, 'w') as f:
        config.write(f)

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_get_sleep_inactive_time(task, data_center):
    """
    get_sleep_inactive_time
    """

    login_id = catch_user_id()
    if login_id == '-':
        task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST
        return
    elif login_id[0] == '+':
        login_id = ''

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {'login_id':login_id}
    server_rsp = data_center.module_request(task)

    sleep_inactive_time = server_rsp[J_MOD][J_TASK][J_RESPONSE]['sleep_inactive_time']
    data_center.GOOROOM_AGENT.sleep_time(int(sleep_inactive_time))
    jlog = 'sleep inactive time has been changed to $({})'.format(sleep_inactive_time)
    send_journallog(jlog, JOURNAL_INFO, GRMCODE_SCREEN_SAVER)

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_sleep_inactive_time(task, data_center):
    """
    sleep inactive time
    """

    login_id = catch_user_id()
    if login_id == '-' or login_id[0] == '+':
        login_id = ''

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {'login_id':login_id}
    server_rsp = data_center.module_request(task)
    sleep_inactive_time = server_rsp[J_MOD][J_TASK][J_RESPONSE]['sleep_inactive_time']
    task[J_MOD][J_TASK][J_OUT]['sleep_inactive_time'] = int(sleep_inactive_time)

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_change_passwd(task, data_center):
    """
    change local passwd
    """

    idpw = task[J_MOD][J_TASK][J_IN]['idpw']
    idpw = json.loads(idpw)
    errmsg = ''
    for ip in idpw:
        try:
            userid = ip['id']
            userpw = ip['pw']

            gecos = getpwnam(userid).pw_gecos.split(',')
            if len(gecos) >= 5 and gecos[4] == 'gooroom-account':
                errmsg += '{} is online account'.format(userid) + '\n'
                continue

            p = subprocess.Popen(
                #['/usr/sbin/chpasswd'], 
                ['/usr/bin/passwd', userid], 
                universal_newlines=True, 
                shell=False,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
                )

            #so, se = p.communicate(userid + ':' + userpw + '\n')
            try:
                so, se = p.communicate(userpw + '\n' + userpw + '\n')
            except:
                pass

            '''
            if so:
                if not isinstance(so, str):
                    so = so.decode('utf8')
                AgentLog.get_logger().info('(change_passwd) sout={}'.format(so))
            if se:
                if not isinstance(se, str):
                    se = se.decode('utf8')
                errmsg += se + '\n'
            '''
        except Exception as e:
            errmsg += e + '\n'

    if errmsg:
        raise Exception(errmsg)
        
#-----------------------------------------------------------------------
def task_expire_passwd(task, data_center):
    """
    expire local passwd
    """

    userid = task[J_MOD][J_TASK][J_IN]['id']
    gecos = getpwnam(userid).pw_gecos.split(',')
    if len(gecos) >= 5 and gecos[4] == 'gooroom-account':
        raise Exception('(expire_passwd) {} is online account'.format(userid))

    #now_date = datetime.datetime.now().strftime('%Y-%m-%d')
    pp = subprocess.Popen(
        ['/usr/bin/chage', '-d', '0', userid],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    sout, serr = pp.communicate()
    if serr:
        raise Exception('(expire_passwd) chage failed:{}'.serr.decode('utf8'))

#-----------------------------------------------------------------------
def task_svr_police_cmd(task, data_center):
    """
    svr_police_cmd
    """

    cmd_id = task[J_MOD][J_TASK][J_IN]['cmd_id']
    if 'cmd_data' in task[J_MOD][J_TASK][J_IN]:
        cmd_data = task[J_MOD][J_TASK][J_IN]['cmd_data']
    else:
        cmd_data = None
    data_len = 1 if cmd_data else 0
    packet = [0,0,0,int(cmd_id),0,0,0,data_len]
    if data_len:
        packet.append(int(cmd_data))
    packet.extend([0x0D, 0x0A])

    police_host = AgentConfig.get_config().get('EXTENSION', 'POLICE_CMD_HOST')
    police_port = AgentConfig.get_config().get('EXTENSION', 'POLICE_CMD_PORT')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sfd:
        sfd.connect((police_host, int(police_port)))
        sfd.sendall(bytes(packet))

#-----------------------------------------------------------------------
def task_get_usb_whitelist_max(task, data_center):
    """
    get_usb_whitelist_max
    """

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {}

    server_rsp = data_center.module_request(task)
    wl_max = server_rsp[J_MOD][J_TASK][J_RESPONSE]['usb_whitelist_max']
    path = AgentConfig.get_config().get('MAIN', 'USB_POLICY_PATH')
    dir_path = '/'.join(path.split('/')[:-1])
    if not os.path.isdir(dir_path):
        os.makedirs(dir_path)

    with open(path, 'w') as f:
        f.write(wl_max)

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def proc_usb_whitelist_state(*args):
    """
    processing usb whitelist state
    """

    state = args[2]
    serial = args[0]

    if state == 'registering-cancel' \
        or state == 'unregister-approval' \
        or state == 'register-deny-item-remove':

        delete_usb_whitelist_state(serial)

    elif state == 'register-approval' \
        or state == 'register-approval-cancel' \
        or state == 'register-deny' \
        or state == 'unregister-deny' \
        or state == 'registering' \
        or state == 'unregistering':

        if state == 'registering':
            delete_usb_whitelist_state(serial)

        update_usb_whitelist_state(*args)

def task_server_event_usb_whitelist(task, data_center):
    """
    server event usb whitelist
    """

    DT = 'datetime'
    UN = 'usb_name'
    UP = 'usb_product'
    USIZE = 'usb_size'
    UV = 'usb_vendor'
    USERIAL = 'usb_serial'
    UM = 'usb_model'
    SEQ = 'req_seq'

    j_in = task[J_MOD][J_TASK][J_IN]
    server_login_id = task[J_MOD][J_TASK][J_IN]['login_id']

    login_id = catch_user_id()
    if login_id == '-' or login_id[0] == '+':
        login_id = ''

    if login_id == server_login_id:
        action = j_in['action']
        userial = j_in[USERIAL]
        dt = j_in[DT] if DT in j_in and j_in[DT] else 'None'
        un = j_in[UN] if UN in j_in and j_in[UN] else 'None'
        up = j_in[UP] if UP in j_in and j_in[UP] else 'None'
        usize = j_in[USIZE] if USIZE in j_in and j_in[USIZE] else 'None'
        uv = j_in[UV] if UV in j_in and j_in[UV] else 'None'
        um = j_in[UM] if UM in j_in and j_in[UM] else 'None'
        seq = j_in[SEQ] if SEQ in j_in and j_in[SEQ] else 'None'

        msg = usb_whitelist_signal_msg(action, userial, un)
        data_center.GOOROOM_AGENT.agent_msg(msg)

        proc_usb_whitelist_state(userial,
                                    dt,
                                    action,
                                    un,
                                    up,
                                    usize,
                                    uv,
                                    um,
                                    seq)

        
    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_client_event_usb_whitelist(task, data_center):
    """
    client event usb whitelist
    """

    login_id = catch_user_id()
    if login_id == '-' or login_id[0] == '+':
        raise Exception('INVALID LOGINID')

    DT = 'datetime'
    UN = 'usb_name'
    UP = 'usb_product'
    USIZE = 'usb_size'
    UV = 'usb_vendor'
    USERIAL = 'usb_serial'
    UM = 'usb_model'
    SEQ = 'req_seq'

    j_in = task[J_MOD][J_TASK][J_IN]
    #action is state
    action = j_in['action']
    userial = j_in[USERIAL]
    dt = j_in[DT] if DT in j_in and j_in[DT] else 'None'
    un = j_in[UN] if UN in j_in and j_in[UN] else 'None'
    up = j_in[UP] if UP in j_in and j_in[UP] else 'None'
    usize = j_in[USIZE] if USIZE in j_in and j_in[USIZE] else 'None'
    uv = j_in[UV] if UV in j_in and j_in[UV] else 'None'
    um = j_in[UM] if UM in j_in and j_in[UM] else 'None'
    seq = j_in[SEQ] if SEQ in j_in and j_in[SEQ] else 'None'

    task[J_MOD][J_TASK][J_REQUEST] = task[J_MOD][J_TASK][J_IN]
    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST]['login_id'] = login_id

    server_rsp = data_center.module_request(task)
    if seq == 'None' and SEQ in server_rsp[J_MOD][J_TASK][J_RESPONSE]:
        seq = server_rsp[J_MOD][J_TASK][J_RESPONSE][SEQ]
    server_state = server_rsp[J_MOD][J_TASK][J_RESPONSE]['state']

    #################### NEW ERROR PROCESSING ###################
    if server_state == 'ERROR':
        task[J_MOD][J_TASK][J_OUT][J_STATUS] = AGENT_NOK

        if J_MESSAGE in server_rsp[J_MOD][J_TASK][J_RESPONSE]:
            task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = \
                server_rsp[J_MOD][J_TASK][J_RESPONSE][J_MESSAGE]
        if 'errorcode' in server_rsp[J_MOD][J_TASK][J_RESPONSE]:
            task[J_MOD][J_TASK][J_OUT]['errorcode'] = \
                server_rsp[J_MOD][J_TASK][J_RESPONSE]['errorcode']
        return
    #############################################################

    if server_state == 'registering-cancel' \
        or server_state == 'register-deny-item-remove' \
        or server_state == 'register-approval' \
        or server_state == 'register-deny' \
        or server_state == 'unregister-approval' \
        or server_state == 'unregister-deny':

        msg = usb_whitelist_signal_msg(server_state, userial, un)
        data_center.GOOROOM_AGENT.agent_msg(msg)

    proc_usb_whitelist_state(userial,
                                dt,
                                server_state,
                                un,
                                up,
                                usize,
                                uv,
                                um,
                                seq)

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_get_secureapp_config(task, data_center):
    """
    get secureapp config
    """

    login_id = catch_user_id()
    if login_id == '-' or login_id[0] == '+':
        login_id = ''

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {'login_id':login_id}
    task[J_MOD][J_TASK][J_REQUEST] = {'require_key':"true"}
    server_rsp = data_center.module_request(task)

    file_name = server_rsp[J_MOD][J_TASK][J_RESPONSE]['file_name']
    file_contents = server_rsp[J_MOD][J_TASK][J_RESPONSE]['file_contents']
    signature = server_rsp[J_MOD][J_TASK][J_RESPONSE]['signature']
    verify_signature(signature, file_contents)
    replace_file(file_name, file_contents, signature)

    create_lsf_public_info(data_center, file_contents)

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_set_authority_config_local(task, data_center):
    """
    set authority config local
    """

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {}

    server_rsp = data_center.module_request(task)
    response = server_rsp[J_MOD][J_TASK][J_RESPONSE]
    polkit_admin = response['polkit_admin']
    polkit_admin_config(polkit_admin)

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def polkit_admin_config(polkit_admin):
    """
    set polkit admin
    """

    try:
        pa_comment = '[Configuration]\nAdminIdentities=unix-{}:{}'
        pa_path = '/etc/polkit-1/localauthority.conf.d/52-gpms.conf'
        if polkit_admin == 'sudo':
            with open(pa_path, 'w') as  f:
                f.write(pa_comment.format('group', 'sudo'))
        elif polkit_admin == 'user':
            login_id = catch_user_id()
            #local user
            if login_id[0] == '+':
                with open(pa_path, 'w') as  f:
                    f.write(pa_comment.format('user', login_id[1:]))
            #remote user, not login
            else:
                with open(pa_path, 'w') as  f:
                    f.write(pa_comment.format('group', 'sudo'))
        else:
            raise Exception('invalid polkit-admin={}'.format(polkit_admin))
    except:
        AgentLog.get_logger().error(agent_format_exc())

def task_get_polkit_admin_config(task, data_center):
    """
    get polkit admin config
    """

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {}

    server_rsp = data_center.module_request(task)
    response = server_rsp[J_MOD][J_TASK][J_RESPONSE]
    polkit_admin = response['polkit_admin']
    polkit_admin_config(polkit_admin)

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def account_config(response):
    """
    enable/disable root/sudo account
    """

    #ROOT USE
    if 'root_use' in response:
        try:
            if response['root_use'] == 'false':
                what_shell = '/usr/sbin/nologin'
            else:
                what_shell = '/bin/bash'
            res = shell_cmd([
                '/usr/sbin/usermod',
                '-s',
                what_shell, 
                'root'])
            AgentLog.get_logger().info('RU-first::'+res)
        except:
            AgentLog.get_logger().warn(agent_format_exc())

        try:
            if response['root_use'] == 'false':
                pw_opt = '-l'
            else:
                pw_opt = '-u'
            res = shell_cmd([
                '/usr/bin/passwd',
                pw_opt,
                'root'])
            AgentLog.get_logger().info('RU-second::'+res)
        except:
            AgentLog.get_logger().warn(agent_format_exc())
            
    #SUDO USE
    if 'sudo_use' in response:
        try:
            if response['sudo_use'] == 'false':
                cmd = '/usr/sbin/deluser'
            else:
                cmd = '/usr/sbin/adduser'
            username = pwd.getpwuid(1000).pw_name
            res = shell_cmd([cmd, username, 'sudo'])
            AgentLog.get_logger().info('MS::'+res)
        except:
            AgentLog.get_logger().warn(agent_format_exc())


def task_get_account_config(task, data_center):
    """
    get_account_config
    """

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {}

    server_rsp = data_center.module_request(task)
    response = server_rsp[J_MOD][J_TASK][J_RESPONSE]
    account_config(response)

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_get_controlcenter_items(task, data_center):
    """
    get_controlcneter_items
    """

    login_id = catch_user_id()
    if login_id == '-' or login_id[0] == '+':
        login_id = ''

    if 'from_gpms' in task[J_MOD][J_TASK][J_IN]:
        from_gpms = True
    else:
        from_gpms = False

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {'login_id':login_id}

    server_rsp = data_center.module_request(task)
    controlcenter_items = \
        server_rsp[J_MOD][J_TASK][J_RESPONSE]['controlcenter_items']

    if from_gpms:
        data_center.GOOROOM_AGENT.controlcenter_items(controlcenter_items)
        
    task[J_MOD][J_TASK][J_OUT]['controlcenter_items'] = controlcenter_items

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def polkit_config(file_contents):
    """
    apply polkit config
    """

    pk = json.loads(file_contents)

    PKLA_PATH = '/etc/polkit-1/localauthority/90-mandatory.d/GPMS.pkla'
    PKLA_TMPL = '[{}]\n'\
                 'Identity=unix-user:*\n'\
                 'Action={}\n'\
                 'ResultAny=no\n'\
                 'ResultInactive=no\n'\
                 'ResultActive={}\n\n'
    contents = ''

    config = AgentConfig.get_config()
    if not 'POLKIT' in config:
        raise Exception('[POLKIT] section not found')

    for pk_name in pk:
        pk_v = pk[pk_name]
        pk_name = pk_name.upper()
        if pk_name in config['POLKIT']:
            action_ids = config['POLKIT'][pk_name]
            contents += PKLA_TMPL.format(pk_name, action_ids, pk_v)
        else:
            AgentLog.get_logger().error(
                '!! {} not found in agent configuration'.format(pk_name))

    PRINTER_BY_AGENT = 'PRINTERBYAGENT'
    if PRINTER_BY_AGENT in config['POLKIT']:
        tmp_ids = config['POLKIT'][PRINTER_BY_AGENT]
        contents += PKLA_TMPL.format(PRINTER_BY_AGENT, tmp_ids, 'yes')

    if contents:
        with open(PKLA_PATH, 'w') as f:
            f.write(contents)
        with open(CONFIG_PATH+'/'+POLKIT_JSON_FILE_NAME, 'w') as f2:
            f2.write(json.dumps(pk))

def task_get_policykit_config(task, data_center):
    """
    get policykit config
    """

    login_id = catch_user_id()
    if login_id == '-' or login_id[0] == '+':
        login_id = ''

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {'login_id':login_id}
    server_rsp = data_center.module_request(task)

    file_name = server_rsp[J_MOD][J_TASK][J_RESPONSE]['file_name']
    file_contents = server_rsp[J_MOD][J_TASK][J_RESPONSE]['file_contents']
    signature = server_rsp[J_MOD][J_TASK][J_RESPONSE]['signature']
    verify_signature(signature, file_contents)
    replace_file(file_name, file_contents, signature)

    polkit_config(file_contents)

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_dpms_off_time(task, data_center):
    """
    dpms off time
    """

    login_id = catch_user_id()
    if login_id == '-' or login_id[0] == '+':
        login_id = ''

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {'login_id':login_id}
    server_rsp = data_center.module_request(task)
    screen_time = server_rsp[J_MOD][J_TASK][J_RESPONSE]['screen_time']
    task[J_MOD][J_TASK][J_OUT]['screen_time'] = int(screen_time)

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_set_homefolder_operation(task, data_center):
    """
    get home folder deletion
    """

    prev_v = data_center.home_folder_delete_flag[0]
    homefolder_operation = \
        task[J_MOD][J_TASK][J_IN]['operation']
    if homefolder_operation == 'enable':
        data_center.home_folder_delete_flag[0] = 'enable'
        lg = 'homefolder operation has been enabled'
        gc = GRMCODE_HOMEFOLDER_OPERATION_ENABLE
    else:
        data_center.home_folder_delete_flag[0] = 'disable'
        lg = 'homefolder operation has been disabled'
        gc = GRMCODE_HOMEFOLDER_OPERATION_DISABLE
    if prev_v != homefolder_operation:
        config = AgentConfig.get_config()
        config.set('CLIENTJOB', 'HOMEFOLDER_OPERATION', homefolder_operation)
        with open(CONFIG_FULLPATH, 'w') as f:
            config.write(f)
        send_journallog(
            lg,
            JOURNAL_INFO, 
            gc)
    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST


#-----------------------------------------------------------------------
def _journal_config(server_rsp, data_center):
    """
    for task_get_log_config and client_sync
    """

    #journal configuration
    journal_conf = \
        json.loads(server_rsp[J_MOD][J_TASK][J_RESPONSE]['journal_conf'])
    is_delete = journal_conf['isDeleteLog']
    remain_days = int(journal_conf['logRemainDate'])
    if is_delete.lower() == 'true':
        remain_days = int(journal_conf['logRemainDate'])
    else:
        remain_days = 0
    if data_center.journal_remain_days != remain_days:
        lm = 'journal configuration has been changed $(logRemainDate:{}->{})'.format(
            data_center.journal_remain_days, remain_days)
        data_center.journal_remain_days = remain_days
        send_journallog(
                    lm, 
                    JOURNAL_INFO, 
                    GRMCODE_JOURNAL_CONFIG_CHANGED)
        config = AgentConfig.get_config()
        config.set('JOURNAL', 'REMAIN_DAYS', str(remain_days))
        with open(CONFIG_FULLPATH, 'w') as f:
            config.write(f)

    max_count = journal_conf['logMaxCount']
    max_size = journal_conf['logMaxSize'] + 'M'
    keep_free = journal_conf['systemKeepFree']

    parser = configparser.RawConfigParser()
    parser.optionxform = str
    parser.read('/etc/systemd/journald.conf')

    old_max_count = parser.get('Journal', 'SystemMaxFiles') \
        if parser.has_option('Journal', 'SystemMaxFiles') else 'NONE'
    old_max_size = parser.get('Journal', 'SystemMaxFileSize') \
        if parser.has_option('Journal', 'SystemMaxFileSize') else 'NONE'
    old_keep_free = parser.get('Journal', 'SystemKeepFree') \
        if parser.has_option('Journal', 'SystemKeepFree') else 'NONE'
    if old_max_size == max_size \
        and old_max_count == max_count \
        and old_keep_free == keep_free:
        return

    lm = 'journal configuration has been changed $('
    if old_max_size != max_size: 
        lm += 'SystemMaxFileSize:{}->{} '.format(old_max_size, max_size)
        parser.set('Journal', 'SystemMaxFileSize', '{}'.format(max_size))
    if old_max_count != max_count: 
        lm += 'SystemMaxFiles:{}->{} '.format(old_max_count, max_count)
        parser.set('Journal', 'SystemMaxFiles', '{}'.format(max_count))
    if old_keep_free != keep_free: 
        lm += 'SystemKeepFree:{}->{} '.format(old_keep_free, keep_free)
        parser.set('Journal', 'SystemKeepFree', '{}'.format(keep_free))
    if parser.has_option('Journal', 'MaxRetentionSec'):
        parser.remove_option('Journal', 'MaxRetentionSec')
    lm += ')' 
    with open('/etc/systemd/journald.conf', 'w') as f:
        parser.write(f)

    send_journallog(
                lm, 
                JOURNAL_INFO, 
                GRMCODE_JOURNAL_CONFIG_CHANGED)

    svc = 'systemd-journald.service'
    m = importlib.import_module('modules.daemon_control')
    tmp_task = \
        {J_MOD:{J_TASK:{J_IN:{'service':svc}, J_OUT:{}}}}
    getattr(m, 'task_daemon_restart')(tmp_task, data_center)

def send_config_diff(file_contents):
    """
    send config diff to journald
    """

    try:
        module_path = \
            AgentConfig.get_config().get('SECURITY', 'SECURITY_MODULE_PATH')
        sys.path.append(module_path)
        m = importlib.import_module('gooroom-security-logparser')
        config_diff = getattr(m, 'config_diff')(file_contents)
        if config_diff:
            send_journallog(
                        config_diff, 
                        JOURNAL_INFO, 
                        GRMCODE_LOG_CONFIG_CHANGED)
    except:
        AgentLog.get_logger().info(agent_format_exc())

def task_get_log_config(task, data_center):
    """
    get log config
    """

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {}
    server_rsp = data_center.module_request(task)

    #log configuration
    file_name = server_rsp[J_MOD][J_TASK][J_RESPONSE]['file_name']
    file_contents = \
        server_rsp[J_MOD][J_TASK][J_RESPONSE]['file_contents']
    signature = \
        server_rsp[J_MOD][J_TASK][J_RESPONSE]['signature']

    send_config_diff(file_contents)

    #if verifying is failed, exception occur
    verify_signature(signature, file_contents)
    replace_file(file_name, file_contents, signature)

    #journal configuration
    _journal_config(server_rsp, data_center)

    #journald vacuum
    remain_days = data_center.journal_remain_days
    if remain_days != 0:
        pp = subprocess.Popen(
            ['/bin/journalctl', '--vacuum-time={}d'.format(remain_days)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        sout, serr = pp.communicate()
        sout = sout.decode('utf8')
        serr = serr.decode('utf8')
        if serr:
            AgentLog.get_logger().info('JOURNALD VACUUM SE:{}'.format(serr))
        if sout:
            AgentLog.get_logger().info('JOURNALD VACUUM SO:{}'.format(sout))
    
    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_get_app_list(task, data_center):
    """
    get_app_list
    """

    login_id = catch_user_id()
    if login_id == '-' or login_id[0] == '+':
        login_id = ''

    if 'from_gpms' in task[J_MOD][J_TASK][J_IN]:
        from_gpms = True
    else:
        from_gpms = False

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {'login_id':login_id}

    server_rsp = data_center.module_request(task)
    black_list = server_rsp[J_MOD][J_TASK][J_RESPONSE]['black_list']

    if from_gpms:
        data_center.GOOROOM_AGENT.app_black_list(black_list)
    else:
        JLOG(GRMCODE_APP_LIST, *('',))
        
    task[J_MOD][J_TASK][J_OUT]['black_list'] = black_list

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_tell_update_operation(task, data_center):
    """
    tell_update_operation
    """

    task[J_MOD][J_TASK][J_OUT]['operation'] = \
        data_center.update_operation[0]
    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
updating_binary = ['/usr/bin/gooroom-update', 
                    '/usr/sbin/synaptic', 
                    '/usr/bin/gooroom-update-launcher']

try:
    with open('/etc/lsb-release', 'r') as ublr:
        ublr_ls = ublr.read().strip().split('\n')
        for ublr_l in ublr_ls:
            ublr_l = ublr_l.strip()
            if ublr_l.startswith('DISTRIB_RELEASE') \
                and int(ublr_l.split('=')[1].strip()[0]) >= 3:
                updating_binary = [ '/usr/sbin/synaptic' ]
except:
    pass

def task_get_update_operation_with_loginid(task, data_center):
    """
    get_update_operation_with_loginid
    """

    login_id = task[J_MOD][J_TASK][J_IN]['login_id']

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {'login_id':login_id}

    server_rsp = data_center.module_request(task)
    operation = server_rsp[J_MOD][J_TASK][J_RESPONSE]['operation']

    if operation == 'enable':
        NO_EXEC = ~stat.S_IXUSR & ~stat.S_IXGRP & ~stat.S_IXOTH
        for ub in updating_binary:
            perm = stat.S_IMODE(os.lstat(ub).st_mode)
            os.chmod(ub, perm & NO_EXEC)
    else:
        EXEC = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        for ub in updating_binary:
            perm = stat.S_IMODE(os.lstat(ub).st_mode)
            os.chmod(ub, perm | EXEC)

    data_center.update_operation[0] = operation
    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_get_update_operation(task, data_center):
    """
    get_update_operation
    """

    login_id = catch_user_id()
    if login_id == '-' or login_id[0] == '+':
        login_id = ''

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {'login_id':login_id}

    server_rsp = data_center.module_request(task)
    operation = server_rsp[J_MOD][J_TASK][J_RESPONSE]['operation']
    jlog = 'update-operation has been {}'.format(operation)

    if operation == 'enable':
        NO_EXEC = ~stat.S_IXUSR & ~stat.S_IXGRP & ~stat.S_IXOTH
        for ub in updating_binary:
            perm = stat.S_IMODE(os.lstat(ub).st_mode)
            os.chmod(ub, perm & NO_EXEC)
        data_center.GOOROOM_AGENT.update_operation(1)
        send_journallog(jlog, JOURNAL_INFO, GRMCODE_UPDATE_OPERATION_ENABLE)
    else:
        EXEC = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        for ub in updating_binary:
            perm = stat.S_IMODE(os.lstat(ub).st_mode)
            os.chmod(ub, perm | EXEC)
        data_center.GOOROOM_AGENT.update_operation(0)
        send_journallog(jlog, JOURNAL_INFO, GRMCODE_UPDATE_OPERATION_DISABLE)

    data_center.update_operation[0] = operation
    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_set_package_operation(task, data_center):
    """
    set_package_operation
    """

    operation = task[J_MOD][J_TASK][J_IN]['operation']

    config = AgentConfig.get_config()
    config.set('MAIN', 'PACKAGE_OPERATION', operation)

    with open(CONFIG_FULLPATH, 'w') as f:
        config.write(f)

    data_center.set_package_operation(operation)
    JLOG(GRMCODE_PUSH_UPDATE, *(operation,))

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_get_package_operation(task, data_center):
    """
    get_package_operation
    """

    task[J_MOD][J_TASK][J_OUT]['operation'] = data_center.package_operation

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_set_hypervisor_operation(task, data_center):
    """
    set_hypervisor_operation
    """

    operation = task[J_MOD][J_TASK][J_IN]['operation']

    svc = 'gop-daemon.service'
    m = importlib.import_module('modules.daemon_control')

    getattr(m, 'task_daemon_status')(
        {J_MOD:{J_TASK:{J_IN:{'service':svc}, J_OUT:{}}}},
        data_center)

    tmp_task = \
        {J_MOD:{J_TASK:{J_IN:{'service':svc, 'operation':operation}, J_OUT:{}}}}

    getattr(m, 'task_daemon_able')(tmp_task, data_center)

#-----------------------------------------------------------------------
def task_get_hypervisor_operation(task, data_center):
    """
    get_hypervisor_operation
    """

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {} #'login_id':catch_user_id()}

    server_rsp = data_center.module_request(task)
    operation = server_rsp[J_MOD][J_TASK][J_RESPONSE]['operation']

    svc = 'gop-daemon.service'
    m = importlib.import_module('modules.daemon_control')

    getattr(m, 'task_daemon_status')(
        {J_MOD:{J_TASK:{J_IN:{'service':svc}, J_OUT:{}}}},
        data_center)

    tmp_task = \
        {J_MOD:{J_TASK:{J_IN:{'service':svc, 'operation':operation}, J_OUT:{}}}}

    getattr(m, 'task_daemon_able')(tmp_task, data_center)

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_set_serverjob_dispatch_time_config(task, data_center):
    """
    set_serverjob_dispatch_time_config
    """

    dispatch_time = task[J_MOD][J_TASK][J_IN]['dispatch_time']

    config = AgentConfig.get_config()
    config.set('SERVERJOB', 'DISPATCH_TIME', dispatch_time)

    with open(CONFIG_FULLPATH, 'w') as f:
        config.write(f)

    data_center.reload_serverjob_dispatch_time()

    update_polling_time_task = {"module":{
                                    "module_name":"config", 
                                    "task":{
                                        "task_name":"update_polling_time", 
                                        "request":{
                                            "polling_time":dispatch_time
                                        }
                                    }
                                }}
    data_center.module_request(update_polling_time_task, mustbedata=False)

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

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

    update_polling_time_task = {"module":{
                                    "module_name":"config", 
                                    "task":{
                                        "task_name":"update_polling_time", 
                                        "request":{
                                            "polling_time":dispatch_time
                                        }
                                    }
                                }}
    data_center.module_request(update_polling_time_task, mustbedata=False)

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def ntp_list_config(ntp_list, data_center):
    """
    real procedure to task_ntp_list_configs
    """

    ntp_conf_path = '/etc/systemd/timesyncd.conf'
    ntp_config = AgentConfig.get_config(ntp_conf_path)
    ntp_config.set('Time', 'NTP', ntp_list)

    with open(ntp_conf_path, 'w') as f:
        ntp_config.write(f)

    #load daemon_control of agent
    svc = 'systemd-timesyncd.service'
    m = importlib.import_module('modules.daemon_control')
    tmp_task = {J_MOD:{J_TASK:{J_IN:{'service':svc}, J_OUT:{}}}}

    #get daemon status
    getattr(m, 'task_daemon_status')(tmp_task, data_center)
    sts = tmp_task[J_MOD][J_TASK][J_OUT]['daemon_status']

    #restart ntp daemon
    if sts.split(',')[0] == 'active':
        getattr(m, 'task_daemon_restart')(tmp_task, data_center)
    else:
        AgentLog.get_logger().info(
            '%s is not active (current status=%s)' % (svc, sts))

def task_set_ntp_list_config(task, data_center):
    """
    set_ntp_list_config
    """

    ntp_list = task[J_MOD][J_TASK][J_IN]['ntp_list']

    ntp_list_config(ntp_list, data_center)

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_get_ntp_list_config(task, data_center):
    """
    get_ntp_list_config
    """

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {}

    server_rsp = data_center.module_request(task)
    ntp_list = server_rsp[J_MOD][J_TASK][J_RESPONSE]['ntp_list']

    ntp_list_config(ntp_list, data_center)

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def _set_time(tp):
    import ctypes
    import ctypes.util
    import time
    import datetime

    class timespec(ctypes.Structure):
        _fields_ = [("tv_sec", ctypes.c_long),
                    ("tv_nsec", ctypes.c_long)]

    librt = ctypes.CDLL(ctypes.util.find_library("rt"))
    ts = timespec()
    ts.tv_sec = int( time.mktime(datetime.datetime(*tp[:6]).timetuple()))
    ts.tv_nsec = tp[6] * 1000000
    librt.clock_settime(0, ctypes.byref(ts)) 

def task_get_server_time(task, data_center):
    """
    get_server_time
    """

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {}

    server_rsp = data_center.module_request(task)
    tl = [int(t) for t in server_rsp[J_MOD][J_TASK][J_RESPONSE]['time'].split(',')]
    _set_time(tuple(tl))

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_get_screen_time(task, data_center):
    """
    get_screen_time
    """

    login_id = catch_user_id()
    if login_id == '-':
        task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST
        return
    elif login_id[0] == '+':
        login_id = ''

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {'login_id':login_id}
    server_rsp = data_center.module_request(task)

    screen_time = server_rsp[J_MOD][J_TASK][J_RESPONSE]['screen_time']
    data_center.GOOROOM_AGENT.dpms_on_x_off(int(screen_time))
    jlog = 'screen-saver time has been changed to $({})'.format(screen_time)
    send_journallog(jlog, JOURNAL_INFO, GRMCODE_SCREEN_SAVER)

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_get_password_cycle(task, data_center):
    """
    get_password_cycle
    """

    login_id = catch_user_id()
    if login_id == '-':
        task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST
        return

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {'login_id':login_id}
    server_rsp = data_center.module_request(task)
    pwd_max_day = server_rsp[J_MOD][J_TASK][J_RESPONSE]['password_time']

    #online account
    if login_id[0] != '+':
        spath = '/home/{}/.gooroom/.grm-user'.format(login_id)

        with open(spath) as f:
            jsondata = json.loads(f.read().strip('\n'))

        if 'pwd_max_day' not in jsondata['data']['loginInfo'] \
            or pwd_max_day != jsondata['data']['loginInfo']['pwd_max_day']:

            jsondata['data']['loginInfo']['pwd_max_day'] = pwd_max_day

            with open(spath, 'w') as f:
                f.write(json.dumps(jsondata))
            
            chown_file(spath, fuser=login_id, fgroup=login_id)
            jlog = 'password cycle has been changed to $({})'.format(pwd_max_day)
            send_journallog(jlog, JOURNAL_INFO, GRMCODE_PASSWORD_CYCLE_LOCAL)
    #local account
    else:
        now_date = datetime.datetime.now().strftime('%Y-%m-%d')
        pp = subprocess.Popen(
            ['/usr/bin/chage', '-d', now_date, '-M', pwd_max_day, login_id[1:]],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        sout, serr = pp.communicate()
        if serr:
            raise Exception('local-count chage-cmd failed:{}'.serr.decode('utf8'))

        jlog = 'password cycle has been changed to $({})'.format(pwd_max_day)
        send_journallog(jlog, JOURNAL_INFO, GRMCODE_PASSWORD_CYCLE_LOCAL)

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_get_update_server_config(task, data_center):
    """
    get_update_server_config
    """

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {}

    server_rsp = data_center.module_request(task)

    filenames = server_rsp[J_MOD][J_TASK][J_RESPONSE]['file_name_list']
    filecontents = server_rsp[J_MOD][J_TASK][J_RESPONSE]['file_contents_list']
    signatures = server_rsp[J_MOD][J_TASK][J_RESPONSE]['signature_list']

    len_filenames = len(filenames)
    len_filecontents = len(filecontents)
    len_signatures = len(signatures)

    if len_filenames != len_filecontents \
        and len_filecontents != len_signatures:
        raise Exception('!! invalid data len(filename)=%d len(filecontents)=%d len(signautres)=%d' 
            % (len_filenames, len_filecontents, len_signatures))
    
    for n, c, s in zip(filenames, filecontents, signatures):
        if c == None or c == '':
            continue
        #if verifying is failed, exception occur
        verify_signature(s, c)
        replace_file(n, c, s)

    cvu = 'Acquire::Check-Valid-Until "false";'
    with open('/etc/apt/apt.conf.d/99gooroom', 'w') as f:
        f.write(cvu)

    apt_exec('update', PKCON_TIMEOUT_ONCE, '', data_center)

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_append_contents_etc_hosts(task, data_center):
    """
    append_contents
    """

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {}

    server_rsp = data_center.module_request(task)

    signature = server_rsp[J_MOD][J_TASK][J_RESPONSE]['signature']
    server_contents = server_rsp[J_MOD][J_TASK][J_RESPONSE]['file_contents']

    #if verifying is failed, exception occur
    verify_signature(signature, server_contents)

    remake_etc_hosts(server_contents, signature)

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def browser_diff(old_fname, new_contents):
    """
    diff browser
    """

    result = ''
    try:
        title = '/'.join(old_fname.split('/')[-3:])
        browser_first_log = True

        with open(old_fname) as f:
            old_contents = f.read()

        oc = nc = {}
        try:
            oc = json.loads(old_contents)
            nc = json.loads(new_contents)
        except:
            #no json
            if old_contents != new_contents:
                result += '[{}]\n{}->{}'.format(title, old_contents, new_contents)
                #print(result)
                return result

        if 'gooroom' in oc and 'policy' in oc['gooroom'] \
            and 'gooroom' in nc and 'policy' in nc['gooroom']: 
            oc = oc['gooroom']['policy']
            nc = nc['gooroom']['policy']

        for new_key in nc.keys():
            if new_key in oc:
                if isinstance(nc[new_key], list) \
                    and isinstance(oc[new_key], list):
                    nset = set(nc[new_key])
                    oset = set(oc[new_key])
                    if nset != oset:
                        result += '{}:{}->{}\n'.format(
                            new_key,
                            oset,
                            nset)
                else:
                    if nc[new_key] != oc[new_key]:
                        if browser_first_log:
                            result += '[{}]\n'.format(title)
                            browser_first_log = False
                        result += '{}:{}->{}\n'.format(
                            new_key,
                            oc[new_key],
                            nc[new_key])

        for old_key in oc.keys():
            if not old_key in nc:
                if browser_first_log:
                    result += '[{}]\n'.format(title)
                    browser_first_log = False
                result += '{} removed'.format(old_key)
    except:
        AgentLog.get_logger().info(agent_format_exc())

    if result:
        result = '\n' + result
        if result[-1] == '\n':
            result = result[:-1]
        #print(result)
    return result

def media_diff(old_fname, new_contents):
    """
    diff media/iptables
    """

    result = ''
    try:
        with open(old_fname) as f:
            old_contents = f.read()

        oc = json.loads(old_contents)
        nc = json.loads(new_contents)

        media_first_log = True
        for media_name in nc.keys():
            if media_name in oc:
                #MEDIA STATE
                old_state = oc[media_name] \
                    if isinstance(oc[media_name], str) \
                    else oc[media_name]['state']

                new_state = nc[media_name] \
                    if isinstance(nc[media_name], str) \
                    else nc[media_name]['state']

                if old_state != new_state:
                    if media_first_log:
                        result += '[media]\n'
                        media_first_log = False
                    result += '{}:{}->{}\n'.format(
                        media_name, old_state, new_state)

                #BLUETOOTH WHITELIST
                oc_whitelist_set = set()
                if isinstance(oc[media_name], dict) \
                    and 'mac_address' in oc[media_name]:
                        oc_whitelist_set = set(oc[media_name]['mac_address'])
                nc_whitelist_set = set()
                if isinstance(nc[media_name], dict) \
                    and 'mac_address' in nc[media_name]:
                        nc_whitelist_set = set(nc[media_name]['mac_address'])
                if oc_whitelist_set != nc_whitelist_set:
                    if media_first_log:
                        result += '[media]\n'
                        media_first_log = False
                    result += '{} whitelist:{}->{}\n'.format(
                        media_name, oc_whitelist_set, nc_whitelist_set)
                    
                #USB WHITELIST
                oc_whitelist_set = set()
                if isinstance(oc[media_name], dict) \
                    and 'usb_serialno' in oc[media_name]:
                        oc_whitelist_set = set(oc[media_name]['usb_serialno'])
                nc_whitelist_set = set()
                if isinstance(nc[media_name], dict) \
                    and 'usb_serialno' in nc[media_name]:
                        nc_whitelist_set = set(nc[media_name]['usb_serialno'])
                if oc_whitelist_set != nc_whitelist_set:
                    if media_first_log:
                        result += '[media]\n'
                        media_first_log = False
                    result += '{} whitelist:{}->{}\n'.format(
                        media_name, oc_whitelist_set, nc_whitelist_set)
            else:
                #skip:never happened
                pass
    except:
        AgentLog.get_logger().info(agent_format_exc())

    try:
        #IPTABLES
        if 'rules' in oc['network']:
            old_network= oc['network']['rules']
        else:
            old_network = []
        if 'rules' in nc['network']:
            new_network= nc['network']['rules']
        else:
            new_network = []

        #old_network= oc['network']['rules']
        #new_network= nc['network']['rules']
        iptables_first_log = True

        ol_list = []
        for ol in old_network:
            m = '{} {} {} {} {} {}'.format(
            ol['ipaddress'].strip(),
            ol['state'].strip(),
            ol['direction'].strip(),
            ol['src_ports'].strip(),
            ol['dst_ports'].strip(),
            ol['protocol'].strip())
            ol_list.append(m)
        nl_list = []
        for nl in new_network:
            m = '{} {} {} {} {} {}'.format(
            nl['ipaddress'].strip(),
            nl['state'].strip(),
            nl['direction'].strip(),
            nl['src_ports'].strip(),
            nl['dst_ports'].strip(),
            nl['protocol'].strip())
            nl_list.append(m)
            
        diff = difflib.ndiff(ol_list, nl_list)
        if diff:
            ll = []
            for l in [d for d in diff if d and d[0] == '-' or d[0] == '+']:
                t = l[1:]
                l = l[0] + t.strip()
                ll.append(l)
            if ll:
                if iptables_first_log:
                    result += '[iptables]\n'
                    iptables_first_log = False
                result += '\n'.join(ll)
    except:
        AgentLog.get_logger().info(agent_format_exc())

    if result:
        result = '\n' + result
        if result[-1] == '\n':
            result = result[:-1]
        #print(result)
    return result

def task_get_media_config(task, data_center):
    """
    get_media_config
    """

    login_id = catch_user_id()
    if login_id == '-' or login_id[0] == '+':
        login_id = ''

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {'login_id':login_id}

    server_rsp = data_center.module_request(task)

    file_name = server_rsp[J_MOD][J_TASK][J_RESPONSE]['file_name']
    file_contents = server_rsp[J_MOD][J_TASK][J_RESPONSE]['file_contents']
    signature = server_rsp[J_MOD][J_TASK][J_RESPONSE]['signature']

    if file_contents and len(file_contents) > 0:
        #if verifying is failed, exception occur
        verify_signature(signature, file_contents)

        #media policy diff
        d_r = media_diff(file_name, file_contents)
        if d_r:
            send_journallog(
                'media policy is changes$({})'.format(d_r),
                JOURNAL_INFO, 
                GRMCODE_CHANGE_MEDIA_POLICY)

        replace_file(file_name, file_contents, signature)

        #reload grac
        svc = 'grac-device-daemon.service'
        m = importlib.import_module('modules.daemon_control')
        tmp_task = \
            {J_MOD:{J_TASK:{J_IN:{'service':svc}, J_OUT:{}}}}
        getattr(m, 'task_daemon_reload')(tmp_task, data_center)

        #USB REGISTER STATE
        '''
        if file_name == '/etc/gooroom/grac.d/user.rules':
            write_usb_register_state(file_contents)
        '''

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def remove_previous_browser_policies():
    """
    remove previous browser policies
    """

    policies = ['/usr/share/gooroom/browser/policies/mainpref.json', 
        '/usr/share/gooroom/browser/policies/trust/managed/policy.json', 
        '/usr/share/gooroom/browser/policies/untrust/managed/policy.json', 
        '/usr/share/gooroom/browser/policies/trust/managed/ui-policy.json', 
        '/usr/share/gooroom/browser/policies/untrust/managed/ui-policy.json']

    for p in policies:
        if os.path.exists(p):
            os.remove(p)
            #print('{} removed'.format(p))
            
def task_get_browser_config(task, data_center):
    """
    get_browser_config
    """

    login_id = catch_user_id()
    if login_id == '-' or login_id[0] == '+':
        login_id = ''

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {'login_id':login_id}

    server_rsp = data_center.module_request(task)

    file_name_list = server_rsp[J_MOD][J_TASK][J_RESPONSE]['file_name_list']
    file_contents_list = server_rsp[J_MOD][J_TASK][J_RESPONSE]['file_contents_list']
    signature_list = server_rsp[J_MOD][J_TASK][J_RESPONSE]['signature_list']

    remove_previous_browser_policies()

    for idx in range(len(file_name_list)):
        file_name = file_name_list[idx]
        file_contents = file_contents_list[idx]
        if not file_contents:
            continue
        signature = signature_list[idx]
        
        #if verifying is failed, exception occur
        verify_signature(signature, file_contents)

        #log policy diff
        d_r = browser_diff(file_name, file_contents)
        if d_r:
            gc = GRMCODE_CHANGE_BROWSER_POLICY
            send_journallog(
                'browser policy is changes$({})'.format(d_r),
                JOURNAL_INFO, 
                GRMCODE_CHANGE_BROWSER_POLICY)

        replace_file(file_name, file_contents, signature)

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_set_authority_config(task, data_center):
    """
    set_authority_config
    """

    login_id = task[J_MOD][J_TASK][J_IN]['login_id']
    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {'login_id':login_id}

    #MACHINE ID
    machineid = ''
    try:
        FPATH = '/etc/machine-id'
        with open(FPATH, 'r') as f:
            machineid = f.read().strip()
            AgentLog.get_logger().info('machine-id={}'.format(machineid))
    except:
        AgentLog.get_logger().error(agent_format_exc())

    task[J_MOD][J_TASK][J_REQUEST]['machineid'] = machineid

    server_rsp = data_center.module_request(task)

    file_name_list = server_rsp[J_MOD][J_TASK][J_RESPONSE]['file_name_list']
    file_contents_list = server_rsp[J_MOD][J_TASK][J_RESPONSE]['file_contents_list']
    signature_list = server_rsp[J_MOD][J_TASK][J_RESPONSE]['signature_list']

    remove_previous_browser_policies()

    #POLICY FILES
    for idx in range(len(file_name_list)):
        try:
            file_name = file_name_list[idx]
            file_contents = file_contents_list[idx]
            signature = signature_list[idx]
            
            #if verifying is failed, exception occur
            verify_signature(signature, file_contents)

            replace_file(file_name, file_contents, signature)

            #POLKIT 
            if file_name.endswith(POLKIT_JSON_FILE_NAME):
                polkit_config(file_contents)

            #USB REGISTER STATE
            if file_name == '/etc/gooroom/grac.d/user.rules':
                write_usb_register_state(file_contents)

        except:
            AgentLog.get_logger().error(agent_format_exc())

    #POLKIT ADMIN
    try:
        response = server_rsp[J_MOD][J_TASK][J_RESPONSE]
        polkit_admin = response['polkit_admin']
        polkit_admin_config(polkit_admin)
    except:
        AgentLog.get_logger().error(agent_format_exc())

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_get_config(task, data_center):
    """
    get_config
    """

    file_name = task[J_MOD][J_TASK][J_IN]['file_name']

    tmpl_path = get_tmpl_path()
    config_file_list = get_enumvalues_from_xml(tmpl_path, 'CONFIG_FILE')


    if not file_name in config_file_list:
        raise Exception('invalid file_name, check config.tmpl')

    with open(file_name) as f:
        file_contents = f.read()
        task[J_MOD][J_TASK][J_OUT]['file_contents'] = file_contents

#-----------------------------------------------------------------------
def get_tmpl_path():
    """
    get module_templates path
    """

    tmpl_path = AgentConfig.get_config().get('MAIN', 'MODULE_TMPL_PATH')
    if tmpl_path[-1] != '/':
        tmpl_path += '/'

    return tmpl_path+'config.tmpl'

#-----------------------------------------------------------------------
def get_enumvalues_from_xml(xmlpath, typename):
    """
    return enum values of <simpleType> of xml
    """

    ns = AgentConfig.get_config().get('MAIN', 'MODULE_TMPL_NAMESPACE')
    tree = etree.parse(xmlpath)
    t_mod = tree.getroot()

    simple_types = t_mod.findall(ns+T_SIMPLETYPE)

    values = []

    for simple_type in simple_types:
        if typename == simple_type.attrib[T_NAME]:
            restrictions = simple_type.findall(ns+T_RESTRICTION)
            for restriction in restrictions:
                enums = restriction.findall(ns+T_SIMPLETYPE_ENUM)
                for enum in enums:
                    values.append(enum.attrib[T_VALUE])

    return values

#-----------------------------------------------------------------------
def allowed_filename(fname, allowed_list):
    """
    check whether fname is allowed in list or not
    """

    import fnmatch
    for allowed in allowed_list:
        if fnmatch.fnmatch(fname, allowed):
            return True
    return False
        
#-----------------------------------------------------------------------
def replace_file(file_name, file_contents, signature=None):
    """
    replace file
    """

    tmpl_path = get_tmpl_path()
    config_file_list = get_enumvalues_from_xml(tmpl_path, 'CONFIG_FILE')

    if not allowed_filename(file_name, config_file_list):
        raise Exception('invalid file_name, check config.tmpl')

    splited = file_name.split('/')
    splited_path = '/'.join(splited[:-1])
    splited_filename = splited[-1]

    if not os.path.isdir(splited_path):
        os.makedirs(splited_path)

    backup_path = AgentConfig.get_config().get('MAIN', 'AGENT_BACKUP_PATH')
    if backup_path[-1] != '/':
        backup_path += '/'

    backupdir_path = '%s%s/' % (backup_path, '.'.join(splited))

    if not os.path.isdir(backupdir_path):
        os.makedirs(backupdir_path)

    if os.path.exists(file_name):
        #최초 원본파일을 보존하기위해서 원본보존파일(+agent_origin)이
        #없으면 현재파일을 복사
        agent_origin = backupdir_path+splited_filename+'+agent_origin'

        if not os.path.exists(agent_origin):
            shutil.copyfile(file_name, agent_origin) 

        #백업파일복사
        agent_prev = backupdir_path+splited_filename+'+agent_prev'

        with open(agent_prev, 'w') as f:
            with open(file_name, 'r') as fin:
                f.write(fin.read())

        #설정파일생성
        with open(file_name, 'w') as f:
            f.write(file_contents)

    else:
        #설정파일이 존재하지 않으면 생성하고 끝.
        #+agent_origin이나 +agent_prev가 존재하는 상태에서 설정파일만 없을 경우는
        #무시해도 생성할 파일이 최신이고 +agent_origin이 원본
        #+agent_prev가 이전파일이라는 지금 로직과 일치함.

        #설정파일생성
        with open(file_name, 'w') as f:
            f.write(file_contents)

    #signature
    if signature:
        with open(backupdir_path+splited_filename+'+signature', 'w') as f:
            f.write(signature)

#-----------------------------------------------------------------------
def assemble_hosts(hosts):
    """
    """

    o = []
    for l in hosts:
        o.append(' '.join(l))

    return '\n'.join(o)

#-----------------------------------------------------------------------
def disassemble_hosts(hosts, local_or_server):
    """
    disassemble each line of hosts
    """

    SVC_NAME = 'generated by gooroom-agent-service'
    result = []

    for line in hosts:
        if local_or_server == 'local' and SVC_NAME in line:
            continue

        l = line.strip().split()

        for i, c in enumerate(l):
            if c[0] == '#':
                s = ' '.join(l[i:])
                del l[i:] 
                l.append(s)

        if local_or_server != 'local':
            l.append('#generated by gooroom-agent-service')

        result.append(l)

    return result

#-----------------------------------------------------------------------
def remake_etc_hosts(contents, signature):
    """
    remake /etc/hosts with altered contents 
    after comparing local contenst with server's
    """

    with open('/etc/hosts') as f:
        local_hosts = disassemble_hosts(f, 'local')
            
    server_contents = contents.strip().rstrip('\n').split('\n')
    server_hosts = disassemble_hosts(server_contents, 'server')

    for server_line in server_hosts:
        server_line = [x for x in server_line if x[0] != '#']
        if len(server_line) < 2:
            continue

        server_domain = server_line[1:]

        for li, local_line in enumerate(local_hosts):
            local_line = [x for x in local_line if x[0] != '#']
        
            if len(local_line) < 2:
                continue
                
            local_domain = local_line[1:]

            gyo_set = set(local_domain) & set(server_domain)
            if gyo_set:
                local_hosts.pop(li)
        
    local_hosts.extend(server_hosts)

    #/etc/hosts에 반영
    replace_file('/etc/hosts', assemble_hosts(local_hosts), signature)

#-----------------------------------------------------------------------
def chown_file(fname, fuser=None, fgroup=None):
    """
    chown of file
    """

    if fuser and fgroup:
        shutil.chown(fname, user=fuser, group=fgroup)

#-----------------------------------------------------------------------
def create_lsf_public_info(data_center, contents):
    """
    create light weight framework public infomation
    """

    c = json.loads(contents)
    public_policy = {}
    public_policy['policy'] = []
    for policy in c['policy']:
        dbus_name = policy['dbus_name']
        if 'public_key' in policy:
            public_key = policy['public_key']
        else:
            public_key = ''
        abs_path = policy['abs_path']
        settings = policy['settings']
        public_policy['policy'].append({'dbus_name':dbus_name,
                                        'public_key':public_key,
                                        'abs_path':abs_path,
                                        'settings':settings})
        
    lsf_public_info_dir = '/'.join(LSF_PUBLIC_INFO_PATH.split('/')[:-1])
    if not os.path.isdir(lsf_public_info_dir):
        os.makedirs(lsf_public_info_dir)

    with open(LSF_PUBLIC_INFO_PATH, 'w') as f:
        f.write(json.dumps(public_policy))

    on_auth = True
    if not data_center.lsf_symm_key \
        or not data_center.lsf_access_token:

        r = lsf_auth(data_center);
        if r != 0:
            on_auth = False

    for p in public_policy['policy']:
        try:
            dname = p['dbus_name']
            m = {}
            shoot = False

            if dname == 'kr.gooroom.ahnlab.v3':
                m['seal'] = {'glyph':'~'}
                m['letter'] = { 
                    'from':'kr.gooroom.gclient',
                    'to':dname,
                    'function':'reload_policy', 
                    'params':{}}
                shoot = True

            elif dname == 'kr.gooroom.ghub':
                if on_auth:
                    m = {}
                    m['seal'] = {'glyph':'{}'.format(LSF_GLYPH_RELOAD)}
                    m['letter'] = {} 
                    shoot = True

            if shoot:
                dobj = '/' + dname.replace('.', '/') + '/LSFO'
                diface = dname + '.LSFI'

                sb = dbus.SystemBus()
                bo = sb.get_object(dname, dobj)
                bi = dbus.Interface(bo, dbus_interface=diface)

                sm = json.dumps(m)
                bi.do_task(sm)
        except:
            AgentLog.get_logger().error(agent_format_exc())

#-----------------------------------------------------------------------
def task_client_sync(task, data_center):
    """
    client sync
    """

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {}

    server_rsp = data_center.module_request(task)

    #SERVER TIME
    try:
        server_time = server_rsp[J_MOD][J_TASK][J_RESPONSE]['time']
        if server_time != '':
            tl = [int(t) for t in server_time.split(',')]
            #_set_time(tuple(tl))
    except:
        AgentLog.get_logger().error(agent_format_exc())

    #POLLING TIME
    try:
        dispatch_time = server_rsp[J_MOD][J_TASK][J_RESPONSE]['dispatch_time']
        if dispatch_time != '':
            config = AgentConfig.get_config()
            config.set('SERVERJOB', 'DISPATCH_TIME', dispatch_time)
            with open(CONFIG_FULLPATH, 'w') as f:
                config.write(f)
            data_center.reload_serverjob_dispatch_time()
            JLOG(GRMCODE_POLLING_TIME, *(dispatch_time,))
    except:
        AgentLog.get_logger().error(agent_format_exc())

    #CERTIFICATE && FILES
    try:
        certificate = server_rsp[J_MOD][J_TASK][J_RESPONSE]['certificate']
        if certificate != '':
            replace_file('/etc/gooroom/agent/server_certificate.crt', certificate)
            JLOG(GRMCODE_CERTIFICATE, *('',))
    except:
        AgentLog.get_logger().error(agent_format_exc())

    try:
        filenames = server_rsp[J_MOD][J_TASK][J_RESPONSE]['file_name_list']
        filecontents = server_rsp[J_MOD][J_TASK][J_RESPONSE]['file_contents_list']
        signatures = server_rsp[J_MOD][J_TASK][J_RESPONSE]['signature_list']

        len_filenames = len(filenames)
        len_filecontents = len(filecontents)
        len_signatures = len(signatures)

        if len_filenames != len_filecontents \
            or len_filecontents != len_signatures:
            raise Exception('!! invalid data len(filename)=%d len(filecontents)=%d len(signautres)=%d' 
                % (len_filenames, len_filecontents, len_signatures))
        
        #check if do pkcon_exec(refresh)
        must_refresh = False
        for idx in range(len(filenames)):
            try:
                n = filenames[idx]
                c = filecontents[idx]
                s = signatures[idx]

                if not c:
                    AgentLog.get_logger().error(
                        '!! filecontents is empty(filename={})'.format(n))
                    continue

                if n == '/etc/hosts':
                    remake_etc_hosts(c, s)
                    continue

                if n == '/usr/lib/gooroom-security-utils/log.conf':
                    send_config_diff(c)

                if n == '/etc/apt/sources.list.d/official-package-repositories.list' \
                    or n == '/etc/apt/preferences.d/gooroom.pref':
                    with open(n, 'r') as f:
                        if c != f.read():
                            must_refresh = True

                #if verifying is failed, exception occur
                verify_signature(s, c)
                replace_file(n, c, s)

                JLOG(GRMCODE_CLIENT_POLICY, *(n,))
            except:
                AgentLog.get_logger().error(agent_format_exc())

        if must_refresh:
            #update cache
            #apt_exec('update', PKCON_TIMEOUT_ONCE, '', data_center)
            pass
    except:
        AgentLog.get_logger().error(agent_format_exc())

    #EMERG
    try:
        apt_exec('update', PKCON_TIMEOUT_ONCE, '', data_center)
    except:
        AgentLog.get_logger().error(agent_format_exc())

    #HOMEFOLDER OPERATION
    try:
        homefolder_operation = \
            server_rsp[J_MOD][J_TASK][J_RESPONSE]['operation']
        if homefolder_operation != data_center.home_folder_delete_flag[0]:
            data_center.home_folder_delete_flag[0] = homefolder_operation
            if homefolder_operation == 'enable':
                lg = 'homefolder operation has been enabled'
                gc = GRMCODE_HOMEFOLDER_OPERATION_ENABLE
            else:
                lg = 'homefolder operation has been disabled'
                gc = GRMCODE_HOMEFOLDER_OPERATION_DISABLE

            config = AgentConfig.get_config()
            config.set('CLIENTJOB', 'HOMEFOLDER_OPERATION', homefolder_operation)
            with open(CONFIG_FULLPATH, 'w') as hf:
                config.write(hf)

            send_journallog(
                lg,
                JOURNAL_INFO, 
                gc)

    except:
        AgentLog.get_logger().error(agent_format_exc())

    #JOURNAL LOG CONFIG
    try:
        _journal_config(server_rsp, data_center)
    except:
        AgentLog.get_logger().error(agent_format_exc())

    #ROOT/SUDO 
    try:
        account_config(server_rsp[J_MOD][J_TASK][J_RESPONSE])
    except:
        AgentLog.get_logger().error(agent_format_exc())

    #POLKIT ADMIN CONFIG
    try:
        response = server_rsp[J_MOD][J_TASK][J_RESPONSE]
        polkit_admin = response['polkit_admin']
        polkit_admin_config(polkit_admin)
    except:
        AgentLog.get_logger().error(agent_format_exc())

    #USB WHITELIST MAX
    try:
        wl_max = server_rsp[J_MOD][J_TASK][J_RESPONSE]['usb_whitelist_max']
        path = AgentConfig.get_config().get('MAIN', 'USB_POLICY_PATH')

        dir_path = '/'.join(path.split('/')[:-1])
        if not os.path.isdir(dir_path):
            os.makedirs(dir_path)

        with open(path, 'w') as f:
            f.write(wl_max)
    except:
        AgentLog.get_logger().error(agent_format_exc())

    #CLEAN MODE
    try:
        clean_mode = \
            server_rsp[J_MOD][J_TASK][J_RESPONSE]['cleanmode_use']
        config = AgentConfig.get_config()
        config.set('CLIENTJOB', 'CLEAN_MODE', clean_mode)
        with open(CONFIG_FULLPATH, 'w') as cm:
            config.write(cm)
    except:
        AgentLog.get_logger().error(agent_format_exc())

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_client_user_sync(task, data_center):
    """
    client user sync
    """

    login_id = catch_user_id()
    if login_id == '-' or login_id[0] == '+':
        login_id = ''

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {'login_id':login_id}

    server_rsp = data_center.module_request(task)

    #NETWORK & MEDIA & BROWSER
    try:
        file_name_list = \
            server_rsp[J_MOD][J_TASK][J_RESPONSE]['file_name_list']
        file_contents_list = \
            server_rsp[J_MOD][J_TASK][J_RESPONSE]['file_contents_list']
        signature_list = \
            server_rsp[J_MOD][J_TASK][J_RESPONSE]['signature_list']

        remove_previous_browser_policies()

        for idx in range(len(file_name_list)):
            try:
                file_name = file_name_list[idx]
                file_contents = file_contents_list[idx]
                if not file_contents:
                    continue
                signature = signature_list[idx]
                
                #if verifying is failed, exception occur
                verify_signature(signature, file_contents)

                replace_file(file_name, file_contents, signature)
                JLOG(GRMCODE_CLIENT_USER_POLICY, *(file_name,))

                #POLKIT 
                if file_name.endswith(POLKIT_JSON_FILE_NAME):
                    polkit_config(file_contents)

                #USB REGISTER STATE
                '''
                if file_name == '/etc/gooroom/grac.d/user.rules':
                    write_usb_register_state(file_contents)
                '''

            except:
                AgentLog.get_logger().error(agent_format_exc())

        #reload grac
        svc = 'grac-device-daemon.service'
        m = importlib.import_module('modules.daemon_control')
        tmp_task = \
            {J_MOD:{J_TASK:{J_IN:{'service':svc}, J_OUT:{}}}}
        getattr(m, 'task_daemon_reload')(tmp_task, data_center)
    except:
        AgentLog.get_logger().error(agent_format_exc())

    #UPDATE OPERATION
    try:
        operation = server_rsp[J_MOD][J_TASK][J_RESPONSE]['operation']
        if not operation:
            raise Exception('update-operation is null')

        if operation == 'enable':
            NO_EXEC = ~stat.S_IXUSR & ~stat.S_IXGRP & ~stat.S_IXOTH
            for ub in updating_binary:
                perm = stat.S_IMODE(os.lstat(ub).st_mode)
                os.chmod(ub, perm & NO_EXEC)
        else:
            EXEC = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            for ub in updating_binary:
                perm = stat.S_IMODE(os.lstat(ub).st_mode)
                os.chmod(ub, perm | EXEC)
        data_center.update_operation[0] = operation
        JLOG(GRMCODE_UPDATER, *(operation,))
    except:
        AgentLog.get_logger().error(agent_format_exc())

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

