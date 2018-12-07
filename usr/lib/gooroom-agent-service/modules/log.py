#! /usr/bin/env python3

#-----------------------------------------------------------------------
import subprocess
import importlib
import datetime
import socket
import glob
import sys
import os

from agent_util import AgentConfig,AgentLog,agent_format_exc,catch_user_id
from agent_util import send_journallog
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
def task_journal_remover(task, data_center):
    """
    journal remover
    """

    remain_days = data_center.journal_remain_days
    if remain_days == 0:
        task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST
        return

    pp = subprocess.Popen(
        ['/bin/journalctl', '--vacuum-time={}d'.format(remain_days)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    sout, serr = pp.communicate()
    sout = sout.decode('utf8')
    serr = serr.decode('utf8')
    if serr:
        AgentLog.get_logger().info(
            'JOURNALD VACUUM FOR OLDER THAN {}days SE:{}'.format(remain_days, serr))
    if sout:
        AgentLog.get_logger().info(
            'JOURNALD VACUUM FRO OLDER THAN {}days SO:{}'.format(remain_days, sout))
    
#-----------------------------------------------------------------------
def task_security_log(task, data_center):
    """
    load security log on journal
    """

    backup_path = AgentConfig.get_config().get('MAIN', 'AGENT_BACKUP_PATH')
    if backup_path[-1] != '/':
        backup_path += '/'

    j = journal.Reader()
    j.seek_tail()
    tail_entry = j.get_previous()
    j.get_next()
    tail_now_timestamp = datetime.datetime.now().timestamp()
    last_seek_time = \
        read_last_seek_time(backup_path, 'gooroom-last-seek-time')

    if tail_entry \
        and tail_entry['__REALTIME_TIMESTAMP'].timestamp() != last_seek_time:
        if last_seek_time:
            j.seek_realtime(round(last_seek_time, 6))
            j.get_next()
        else:
            j.seek_head()
        
        logs = {}
        logs_len = 0
        MAX_LOG_LEN = int(AgentConfig.get_config().get('MAIN', 'MAX_LOG_LEN'))

        module_path = \
            AgentConfig.get_config().get('SECURITY', 'SECURITY_MODULE_PATH')
        sys.path.append(module_path)
        m = importlib.import_module('gooroom-security-logparser')
        #GET LOG
        logs = getattr(m, 'get_summary')(j)
        log_total_len = logs['log_total_len']

        if log_total_len > 0 or data_center.summary_log_first_execution:
            data_center.summary_log_first_execution = False

            if log_total_len <= MAX_LOG_LEN:
                task[J_MOD][J_TASK].pop(J_IN)
                task[J_MOD][J_TASK][J_REQUEST] = {}
                task[J_MOD][J_TASK][J_REQUEST]['logs'] = logs
                data_center.module_request(task, mustbedata=False)
                
            else:
                for l in logs.keys():
                    if l.endswith('_log'):
                        logs[l] = []

                if not 'agent_log' in logs:
                    logs['agent_log'] = []

                t = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
                m = 'LOG SIZE IS TOO BIG({})'.format(log_total_len)
                logs['agent_log'] = [{'grmcode':'',
                                        'level':'crit',
                                        'log':m,
                                        'type':1,
                                        'time':t,
                                        'eval_level':'AGENT-EXPRESS'}]
                AgentLog.get_logger().error(m)

        last_seek_time = tail_entry['__REALTIME_TIMESTAMP'].timestamp()

        if not isinstance(last_seek_time, float) or last_seek_time <= 0.0:
            AgentLog.get_logger().info(
                '(gooroom_log) invalid last_seek_time={} type={}'.format(
                                    last_seek_time, type(last_seek_time)))
            last_seek_time = tail_now_timestamp

        #save lask seek_time to file
        write_last_seek_time(backup_path, last_seek_time, 'gooroom-last-seek-time')

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_clear_security_alarm(task, data_center):
    """
    clear_security_alarm
    """

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {}

    data_center.module_request(task, mustbedata=False)

    logparser_path = \
        AgentConfig.get_config().get('MAIN', 'LOGPARSER_SEEKTIME_PATH')

    seek_time = datetime.datetime.now().strftime('%Y%m%d-%H%M%S.%f')
    with open(logparser_path, 'w') as f:
        f.write(seek_time)
    
    lg = 'alert has been released'
    gc = GRMCODE_ALERT_RELEASE
    send_journallog(lg, JOURNAL_NOTICE, gc)

#-----------------------------------------------------------------------
def task_client_info(task, data_center):
    """
    client_info
    """

    unique_id = read_unique_id()
    os_ver = read_os()
    kernel = read_kernel()
    ip = remote_ipaddress()
    home_size ,home_used = homedir_size()
    pss = '-1,-1' #','.join(calc_pss())
    
    info_set = {
                unique_id, 
                os_ver, 
                kernel, 
                ip, 
                home_size, 
                int(home_used/100000000), #100M 이하의 변화는 무시 
                pss }
    if data_center.client_info_set == info_set:
        task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST
        return
                                        
    data_center.client_info_set = info_set

    task[J_MOD][J_TASK][J_OUT]['terminal_info'] = \
        '%s,%s,%s,%s,%d,%d' % (
                                unique_id, 
                                os_ver, 
                                kernel, 
                                ip,
                                home_size,
                                home_used)
    
    task[J_MOD][J_TASK][J_OUT]['safe_score'] = pss
    
#-----------------------------------------------------------------------
def read_last_seek_time(backup_path, fname):
    """
    read last seek time from file
    """

    fullpath = backup_path+fname 

    if not os.path.exists(fullpath):
        return None

    with open(fullpath) as f:
        t = f.readline().strip().rstrip('\n')
        if not t:
            t = None

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
def read_unique_id():
    """
    return client unique id
    """

    if os.path.exists('/sys/devices/virtual/dmi/id/product_uuid'): 
        with open('/sys/devices/virtual/dmi/id/product_uuid') as f:
            return f.read().strip('\n')
    else:
        for iface in glob.glob('/sys/class/net/*'):
            if iface == '/sys/class/net/lo':
                continue
            with open(iface+'/address') as f2:
                return f2.read().strip('\n')

    return 'no unique id'

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
def remote_ipaddress():
    """
    get remote ip address
    """

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('8.8.8.8', 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except:
        logger.info(agent_format_exc())
        return ''

#-----------------------------------------------------------------------
def homedir_size():
    """
    get home directory full size and used size
    """

    try:
        p = subprocess.Popen(
            ['df', '-B1'], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE)

        sout, serr = p.communicate()
        if serr:
            logger.info(serr)
            return -1, -1

        sout = sout.decode('utf8')
        infos = [l.split() for l in sout.split('\n')]
        root_full_size = root_used_size = 0
        home_full_size = home_used_size = 0
        root_found = home_found = False

        for info in infos:
            if len(info) < 6:
                continue
            mounted = info[5].strip()
            if mounted == '/':
                root_full_size = int(info[1].strip())
                root_used_size = int(info[2].strip())
                root_found = True
            elif mounted.startswith('/home'):
                home_full_size += int(info[1].strip())
                home_used_size += int(info[2].strip())
                home_found = True

        if home_found:
            return home_full_size, home_used_size
        elif root_found:
            return root_full_size, root_used_size
    except:
        logger.info(agent_format_exc())
        return -1, -1
