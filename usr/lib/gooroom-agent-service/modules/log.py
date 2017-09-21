#! /usr/bin/env python3

#-----------------------------------------------------------------------
import subprocess
import importlib
import datetime
import sys
import os

from agent_util import AgentConfig,AgentLog,agent_format_exc,catch_user_id
from agent_define import *
from systemd import journal

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

#-----------------------------------------------------------------------
PRIORITY_N_TO_S = {
        0:'EMERG',
        1:'ALERT',
        2:'CRIT',
        3:'ERR',
        4:'WARNING',
        5:'NOTICE',
        6:'INFO',
        7:'DEBUG'}

def task_gooroom_log(task, data_center):
    """
    load gooroom log on journal
    """

    gooroom_match_strings = (
        'SYSLOG_IDENTIFIER=gooroom-browser', 
        'SYSLOG_IDENTIFIER=grac-device-daemon',
        'PRIORITY=%s' % data_center.journal_loglevel)

    backup_path = AgentConfig.get_config().get('MAIN', 'AGENT_BACKUP_PATH')
    if backup_path[-1] != '/':
        backup_path += '/'

    j = journal.Reader()

    j.seek_tail()
    tail_entry = j.get_previous()

    last_seek_time = read_last_seek_time(backup_path, 'gooroom-last-seek-time')

    if tail_entry and tail_entry['__REALTIME_TIMESTAMP'].timestamp() != last_seek_time:

        if last_seek_time:
            j.seek_realtime(round(last_seek_time+0.000001, 6))
        else:
            j.seek_head()
        
        for match in gooroom_match_strings:
            j.add_match(match)
            j.add_disjunction()

        logs = {}

        for entry in j:
            if 'SYSLOG_IDENTIFIER' in entry and 'MESSAGE' in entry:
                ident = entry['SYSLOG_IDENTIFIER']    
                dt = entry['__REALTIME_TIMESTAMP'].strftime('%Y-%m-%d %H:%M:%S.%f')
                msg = entry['MESSAGE']
                priority = PRIORITY_N_TO_S[entry['PRIORITY']]
                
                logs.setdefault(ident, []).append(
                    '%s,,,%s,,,%s' % (dt, priority, msg))

            if tail_entry['__CURSOR'] == entry['__CURSOR']:
                break

        if len(logs) > 0:
            task[J_MOD][J_TASK].pop(J_IN)
            task[J_MOD][J_TASK][J_REQUEST] = {}
            task[J_MOD][J_TASK][J_REQUEST]['user_id'] = catch_user_id()
            task[J_MOD][J_TASK][J_REQUEST]['logs'] = logs

            #if no exception, it's OK
            data_center.module_request(task, mustbedata=False)

        last_seek_time = tail_entry['__REALTIME_TIMESTAMP'].timestamp()

        #save lask seek_time to file
        write_last_seek_time(backup_path, last_seek_time, 'gooroom-last-seek-time')

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_clear_security_alarm(task, data_center):
    """
    clear_cecurity_alarm
    """

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {}

    data_center.module_request(task, mustbedata=False)

    logparser_path = \
        AgentConfig.get_config().get('MAIN', 'LOGPARSER_SEEKTIME_PATH')

    seek_time = datetime.datetime.now().strftime('%Y%m%d-%H%M%S.%f')
    with open(logparser_path, 'w') as f:
        f.write(seek_time)
    
#-----------------------------------------------------------------------
def task_client_info(task, data_center):
    """
    client_info
    """

    unique_id = read_unique_id()
    os_ver = read_os()
    kernel = read_kernel()
    ip = ''
    
    task[J_MOD][J_TASK][J_OUT]['terminal_info'] = \
        '%s,%s,%s,%s' % (unique_id, os_ver, kernel, ip)
    
    task[J_MOD][J_TASK][J_OUT]['safe_score'] = ','.join(calc_pss())
    
#-----------------------------------------------------------------------
def task_summary_log(task, data_center):
    """
    summary_log
    """

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {}

    task[J_MOD][J_TASK][J_REQUEST]['user_id'] = catch_user_id()

    load_security_log(task, data_center)

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def read_last_seek_time(backup_path, fname):
    """
    read last seek time from file
    """

    fullpath = backup_path+fname 

    if not os.path.exists(fullpath):
        return None

    t = None
    with open(fullpath) as f:
        t = f.readline().strip().rstrip('\n')

    return float(t)

#-----------------------------------------------------------------------
def write_last_seek_time(backup_path, next_seek_time, fname):
    """
    write last seek time to file
    """

    if not os.path.isdir(backup_path):
        os.makedirs(backup_path)

    with open(backup_path+fname, 'w') as f:
        f.write(str(next_seek_time))


#-----------------------------------------------------------------------
def calc_pss():
    """
    return calculated pss score
    """

    try:
        logger= AgentLog.get_logger()

        module_path = AgentConfig.get_config().get('SECURITY', 'PSS_MODULE_PATH')
        sys.path.append(module_path)

        m = importlib.import_module('pss')
        file_num, score = getattr(m, 'PSS')(logger).run()
        return str(file_num), str(score)

    except:
        e = agent_format_exc()
        logger.info(e)
        return '-1', '-1'

#-----------------------------------------------------------------------
match_strings = (
    'SYSLOG_IDENTIFIER=gbp-daemon', 
    'SYSLOG_IDENTIFIER=gep-daemon',
    'SYSLOG_IDENTIFIER=gop-daemon', 
    'SYSLOG_IDENTIFIER=grac-device-daemon',
    'PRIORITY=3',
    '_AUDIT_FIELD_OP="appraise_data"')

def load_security_log(task, data_center):
    """
    load security log on journal
    """

    backup_path = AgentConfig.get_config().get('MAIN', 'AGENT_BACKUP_PATH')
    if backup_path[-1] != '/':
        backup_path += '/'

    j = journal.Reader()

    j.seek_tail()
    tail_entry = j.get_previous()

    last_seek_time = read_last_seek_time(backup_path, 'security-last-seek-time')

    if tail_entry and tail_entry['__REALTIME_TIMESTAMP'].timestamp() != last_seek_time:

        if last_seek_time:
            j.seek_realtime(round(last_seek_time+0.000001, 6))
        else:
            j.seek_head()
        
        for match in match_strings:
            j.add_match(match)
            j.add_disjunction()

        logs = []

        for entry in j:
            if 'MESSAGE' in entry and type(entry['MESSAGE']) is bytes:
                entry['MESSAGE'] = \
                    str(entry['MESSAGE'].decode('unicode_escape').encode('utf-8'))

            logs.append(entry)

            if tail_entry['__CURSOR'] == entry['__CURSOR']:
                break

        #load modules
        module_path = AgentConfig.get_config().get('SECURITY', 'SECURITY_MODULE_PATH')
        sys.path.append(module_path)

        #invoke get_summary
        sendable = False
        for sf in ('os', 'exe', 'boot', 'media'):
            try:
                m = importlib.import_module('security.'+sf)
                run, status, log = getattr(m, 'get_summary')(logs)

                if not log:
                    continue

                task[J_MOD][J_TASK][J_REQUEST][sf+'_run'] = run
                task[J_MOD][J_TASK][J_REQUEST][sf+'_status'] = status
                task[J_MOD][J_TASK][J_REQUEST][sf+'_log'] = '\n'.join(log)

                sendable = True

            except:
                e = agent_format_exc()
                AgentLog.get_logger().info(e)
            
        #if no exception, it's OK
        if sendable:
            data_center.module_request(task, mustbedata=False)

        last_seek_time = tail_entry['__REALTIME_TIMESTAMP'].timestamp()

        #save lask seek_time to file
        write_last_seek_time(backup_path, last_seek_time, 'security-last-seek-time')

#-----------------------------------------------------------------------
def read_unique_id():
    """
    return client unique id
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

