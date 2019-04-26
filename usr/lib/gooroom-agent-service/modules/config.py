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
import pwd
import sys
import os
import re

from multiprocessing import Process
import difflib

from agent_util import pkcon_exec,verify_signature,send_journallog,apt_exec
from agent_util import AgentConfig,AgentLog,agent_format_exc,catch_user_id
from agent_util import shell_cmd,JLOG
from agent_define import *

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
def task_dpms_off_time(task, data_center):
    """
    dpms off time
    """

    if 'login_id' in task[J_MOD][J_TASK][J_IN]:
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
            login_id = ''
    else:
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

    if 'login_id' in task[J_MOD][J_TASK][J_IN]:
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
            login_id = ''
    else:
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
def task_set_gpg_key(task, data_center):
    """
    set_gpg_key
    """

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {}

    AGENT_MARK = 'AGENT-'
    path = '/etc/apt/trusted.gpg.d/'
    mch = re.compile(AGENT_MARK)

    for old_fname in (f for f in glob.glob(path+'*') if mch.search(f)):
        os.remove(old_fname)

    server_rsp = data_center.module_request(task)
    urls = server_rsp[J_MOD][J_TASK][J_RESPONSE]['update_base_urls'].split('\n')

    gpg = gnupg.GPG(gnupghome='/var/tmp/gooroom-agent-service')
    try:
        for url in urls:
            domain = url.split()[1].strip()
            proto_len = 0
            if domain.startswith('https://'):
                proto_len = 8
            elif domain.startswith('http://'):
                proto_len = 7

            if proto_len == 0:
                continue

            protocol = domain[:proto_len]
            hostname = domain[proto_len:].split('/')[0]
            agent_http = httplib2.Http(ca_certs=data_center.agent_ca_cert, 
                    timeout=data_center.rest_timeout)
            agent_http.add_certificate(key=data_center.agent_key, 
                    cert=data_center.agent_cert, domain='')
            rsp_headers, rsp_body = \
                agent_http.request(protocol+hostname+'/archive.key', method='GET')

            if rsp_headers['status'] == '200':
                new_fname = path+AGENT_MARK + hostname.replace('.', '-') +'.gpg'
                res = gpg.import_keys(rsp_body)
                os.chmod('/var/tmp/gooroom-agent-service/pubring.gpg', 644)
                shutil.copyfile('/var/tmp/gooroom-agent-service/pubring.gpg', new_fname)
                AgentLog.get_logger().info('GPG KEY OK')
    except:
        AgentLog.get_logger().info(agent_format_exc())

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
ATP_CONF_TEMPL = '''APT::Sandbox::User "root";

Acquire::https::%s {
    Verify-Peer "true";
    Verify-Host "true";

    SslCert "%s";
    SslKey "%s";
}'''

def task_set_apt_conf(task, data_center):
    """
    set_apt_conf
    """

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {}

    server_rsp = data_center.module_request(task)
    urls = server_rsp[J_MOD][J_TASK][J_RESPONSE]['update_base_urls'].split('\n')

    AGENT_MARK = 'AGENT-'
    path = '/etc/apt/apt.conf.d/'
    mch = re.compile(AGENT_MARK)

    cert_path = AgentConfig.get_config().get('MAIN', 'AGENT_CERT')
    key_path = AgentConfig.get_config().get('MAIN', 'AGENT_KEY')

    for old_fname in (f for f in glob.glob(path+'*') if mch.search(f)):
        os.remove(old_fname)

    try:
        for url in urls:
            domain = url.split()[1].strip()
            if not domain.startswith('https://'):
                continue

            proto_len = 8
            hostname = domain[proto_len:].split('/')[0]
            agent_http = httplib2.Http(timeout=data_center.rest_timeout)
            rsp_headers, rsp_body = agent_http.request(domain, method='GET')

            if rsp_headers['status'] == '400':
                new_fname = path + '20' + AGENT_MARK + hostname.replace('.', '-')
                with open(new_fname, 'w') as f:
                    f.write(ATP_CONF_TEMPL % (hostname, cert_path, key_path))

                AgentLog.get_logger().info('APT CONF OK')
    except:
        AgentLog.get_logger().info(agent_format_exc())

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST


#-----------------------------------------------------------------------
def task_tell_update_operation(task, data_center):
    """
    tell_update_operation
    """

    '''
    login_id = catch_user_id()
    if data_center.server_version == SERVER_VERSION_1_0:
        if login_id == '-':
            raise Exception('The client did not log in.')
        elif login_id[0] == '+':
            raise Exception('The client logged in as local user.')
    else:
        if login_id == '-' or login_id[0] == '+':
            login_id = ''

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {'login_id':login_id}

    server_rsp = data_center.module_request(task)
    operation = server_rsp[J_MOD][J_TASK][J_RESPONSE]['operation']
    '''

    task[J_MOD][J_TASK][J_OUT]['operation'] = \
        data_center.update_operation[0]
    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
updating_binary = ['/usr/bin/gooroom-update', 
                    '/usr/sbin/synaptic', 
                    '/usr/bin/gooroom-update-launcher']

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
    if data_center.server_version.startswith(SERVER_VERSION_1_0):
        if login_id == '-':
            raise Exception('The client did not log in.')
        elif login_id[0] == '+':
            raise Exception('The client logged in as local user.')
    else:
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
def task_get_server_certificate(task, data_center):
    """
    get_server_certificate
    """

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {}

    server_rsp = data_center.module_request(task)

    file_contents = server_rsp[J_MOD][J_TASK][J_RESPONSE]['file_contents']

    replace_file('/etc/gooroom/agent/server_certificate.crt', file_contents)

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

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
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

#-----------------------------------------------------------------------
def task_get_screen_time(task, data_center):
    """
    get_screen_time
    """

    login_id = catch_user_id()
    if data_center.server_version.startswith(SERVER_VERSION_1_0):
        if login_id == '-':
            raise Exception('The client did not log in.')
        elif login_id[0] == '+':
            raise Exception('The client logged in as local user.')
    else:
        #not logged in
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
    if data_center.server_version.startswith(SERVER_VERSION_1_0):
        if login_id == '-':
            raise Exception('The client did not log in.')
        elif login_id[0] == '+':
            raise Exception('The client logged in as local user.')
    else:
        #not logged in
        if login_id == '-':
            task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST
            return

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {'login_id':login_id}
    server_rsp = data_center.module_request(task)
    pwd_max_day = server_rsp[J_MOD][J_TASK][J_RESPONSE]['password_time']

    #online account
    if login_id[0] != '+':
        spath = '/var/run/user/%s/gooroom/.grm-user' % pwd.getpwnam(login_id).pw_uid

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
    '''
    import apt_pkg
    apt_pkg.init()
    cache = apt.cache.Cache()
    cache.update()
    cache.open()
    cache.close()
    '''

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
    if data_center.server_version.startswith(SERVER_VERSION_1_0):
        if login_id == '-':
            raise Exception('The client did not log in.')
        elif login_id[0] == '+':
            raise Exception('The client logged in as local user.')
    else:
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
    if data_center.server_version.startswith(SERVER_VERSION_1_0):
        if login_id == '-':
            raise Exception('The client did not log in.')
        elif login_id[0] == '+':
            raise Exception('The client logged in as local user.')
    else:
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

    server_rsp = data_center.module_request(task)

    file_name_list = server_rsp[J_MOD][J_TASK][J_RESPONSE]['file_name_list']
    file_contents_list = server_rsp[J_MOD][J_TASK][J_RESPONSE]['file_contents_list']
    signature_list = server_rsp[J_MOD][J_TASK][J_RESPONSE]['signature_list']

    remove_previous_browser_policies()

    for idx in range(len(file_name_list)):
        file_name = file_name_list[idx]
        if '$(LOGINID)' in file_name:
            file_name = \
                file_name.replace('$(LOGINID)', '%s' % login_id)

        file_contents = file_contents_list[idx]
        signature = signature_list[idx]
        
        #if verifying is failed, exception occur
        verify_signature(signature, file_contents)

        replace_file(file_name, file_contents, signature)

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
def apply_local_account_config(server_rsp, data_center):
    """
    apply get-local-account-config
    """

    response = server_rsp[J_MOD][J_TASK][J_RESPONSE]

    #ROOT USE
    if 'root_use' in response:
        try:
            if response['root_use'] == 'disable':
                what_shell = '/usr/sbin/nologin'
            else:
                what_shell = '/bin/bash'
            res = shell_cmd([
                '/usr/sbin/usermod',
                '-s',
                what_shell, 
                'root'])
            AgentLog.get_logger().info('RU::'+res)
        except:
            AgentLog.get_logger().error(agent_format_exc())
            
    #MAKING SUDOER
    if 'making_sudoer' in response:
        try:
            ms = response['making_sudoer']
            user_id = ms['user_id']
            salt = ms['salt']
            hash_v = ms['hash']
            #assume algorithm  is sha512
            algo = ms['algo']

            #check if gpms account exists in local
            users = shell_cmd(['/usr/bin/getent', 'passwd']).split('\n')
            status = 'make'
            for user in users:
                if not user:
                    continue
                user_info = user.split(':')
                user_id = user_info[0]
                uid = int(user_info[2])
                if user_id == user:
                    if uid == 800:
                        status = 'make'
                    else:
                        status = 'already'
                    break
                elif uid == 800:
                    status = 'remake'
                    break

            if status == 'already':
                raise Exception('userid({}) is one of local users')
                
            if status == 'remake':
                res = shell_cmd(['/usr/sbin/deluser', user_id])
                AgentLog.get_logger().info('MS::'+res)

            #create user
            if status == 'make' or status == 'remake':
                res = shell_cmd([
                    '/usr/sbin/adduser', 
                    '--disabled-password',
                    '--gecos',
                    '""',
                    '-u',
                    '800',
                    user_id])
                AgentLog.get_logger().info('MS::'+res)

                res = shell_cmd(['/usr/sbin/adduser', user_id, 'sudo'])
                AgentLog.get_logger().info('MS::'+res)

            #change password
            with open('/etc/shadow', 'r') as f:
                shadows = f.read()
            AGENT_OWN_DIR = \
                AgentConfig.get_config().get('MAIN', 'AGENT_OWN_DIR')
            with open(AGENT_OWN_DIR+'/shadow.new', 'w') as f:
                for shadow in shadows:
                    splited = shadow.split(':')
                    if splited[0] == user_id:
                        #algo is assumed to be sha512 and is ignored
                        splited[1] = '$6${}${}'.format(salt, hash_v)
                        f.write('{}\n'.format(':'.join(splited)))
                    else:
                        f.write('{}\n'.fomat(shadow))
        except:
            AgentLog.get_logger().error(agent_format_exc())
            
    #LOCAL SUDOER USE
    if 'local_sudoer_use' in response:
        try:
            res = shell_cmd(['/usr/bin/getent', 'group', 'sudo'])
            AgentLog.get_logger().info('LS::'+res)
            sudoers = res.split(':')[-1].split(',')

            if response['local_sudoer_use'] == 'disable':
                what_shell = '/usr/bin/nologin'
            else:
                what_shell = '/bin/bash'

            users = shell_cmd(['/usr/bin/getent', 'passwd']).split('\n')
            for user in users:
                if not user:
                    continue
                user_info = user.split(':')
                if len(user_info) < 3:
                    continue
                uid = int(user_info[2])
                if uid < 1000: #skip gpms and system account
                    continue
                user_id = user_info[0]
                if not user_id in sudoers:
                    continue
                res = shell_cmd(
                    ['/usr/sbin/usermod', '-s', what_shell, user_id])
                AgentLog.get_logger().info('LS::'+res)
        except:
            AgentLog.get_logger().error(agent_format_exc())

    #LOCAL ACCOUNT USE
    if 'local_account_use' in response:
        try:
            res = shell_cmd(['/usr/bin/getent', 'group', 'sudo'])
            AgentLog.get_logger().info('LA::'+res)
            sudoers = res.split(':')[-1].split(',')

            if response['local_account_use'] == 'disable':
                what_shell = '/usr/bin/nologin'
            else:
                what_shell = '/bin/bash'

            users = shell_cmd(['/usr/bin/getent', 'passwd']).split('\n')
            for user in users:
                if not user:
                    continue
                user_info = user.split(':')
                if len(user_info) < 3:
                    continue
                uid = int(user_info[2])
                if uid < 1000: #skip gpms and system account
                    continue
                user_id = user_info[0]
                if user_id in sudoers:
                    continue
                res = shell_cmd(
                    ['/usr/sbin/usermod', '-s', what_shell, user_id])
                AgentLog.get_logger().info('LA::'+res)
        except:
            AgentLog.get_logger().error(agent_format_exc())

#-----------------------------------------------------------------------
def apply_remote_account_privilege(server_rsp, data_center):
    """
    apply get-remote-account-privilege
    """

    response = server_rsp[J_MOD][J_TASK][J_RESPONSE]

    if 'network_privilege' in response:
        try:
            if response['network_privilege'] == 'disable':
                text = 'auth_admin'
            else:
                text = 'yes'
            np_path = \
                '/usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy'
            if os.path.exists(np_path):
                tree = etree.parse(np_path).getroot()
                policyconfig = tree.getroot()

                for action in policyconfig.findall('action'):
                    if action.attrib['id'] == \
                        'org.freedesktop.NetworkManager.network-control':
                        action.find('defaults').find('allow_inactive').text = text
                        action.find('defaults').find('allow_active').text = text

                tree.write(np_path, encoding="UTF-8",xml_declaration=True)
        except:
            AgentLog.get_logger().error(agent_format_exc())

    if 'update_privilege' in response:
        try:
            if response['update_privilege'] == 'disable':
                text = 'auth_admin'
            else:
                text = 'yes'
            np_path = \
                '/usr/share/polkit-1/actions/com.ubuntu.pkexec.synaptic.policy'
            if os.path.exists(np_path):
                tree = etree.parse(np_path).getroot()
                policyconfig = tree.getroot()

                for action in policyconfig.findall('action'):
                    if action.attrib['id'] == \
                        'com.ubuntu.pkexec.synaptic':
                        action.find('defaults').find('allow_inactive').text = text
                        action.find('defaults').find('allow_active').text = text

                tree.write(np_path, encoding="UTF-8",xml_declaration=True)
            pass
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

    #HYPERVISOR
    try:
        hyper_operation = server_rsp[J_MOD][J_TASK][J_RESPONSE]['hyper_operation']
        if hyper_operation != '':
            svc = 'gop-daemon.service'
            m = importlib.import_module('modules.daemon_control')
            tmp_task = \
                {J_MOD:{J_TASK:{J_IN:{'service':svc, 'operation':hyper_operation}, J_OUT:{}}}}
            getattr(m, 'task_daemon_able')(tmp_task, data_center)
            JLOG(GRMCODE_HYPERVISOR, *(hyper_operation,))
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

    #LOCAL ACCOUNT CONFIG
    try:
        apply_local_account_config(server_rsp, data_center)
    except:
        AgentLog.get_logger().error(agent_format_exc())
        
    #REMOTE ACCOUNT PRIVILEGE
    try:
        apply_remote_account_privilege(server_rsp, data_center)
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
