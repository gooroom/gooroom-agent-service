#! /usr/bin/env python3

#-----------------------------------------------------------------------
import simplejson as json
import subprocess
import importlib
import netifaces
import ipaddress
import datetime
import socket
import glob
import dbus
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
def task_app_info(task, data_center):
    """
    app_info
    """

    dname = 'kr.gooroom.ahnlab.v3'
    dobj = '/' + dname.replace('.', '/') + '/LSFO'
    diface = dname + '.LSFI'

    sb = dbus.SystemBus()
    bo = sb.get_object(dname, dobj)
    bi = dbus.Interface(bo, dbus_interface=diface)

    m = {}
    m['seal'] = {'glyph':'~'}
    m['letter'] = { 
        'from':'kr.gooroom.gclient',
        'to':dname,
        'function':'get_stats', 
        'params':{}}

    sm = json.dumps(m)
    app_resp_string = bi.do_task(sm)
    app_resp = json.loads(app_resp_string)['letter']

    if app_resp['return']['status'] == 'success':
        v = app_resp['return']['values']

        #diff response and saved info

        task[J_MOD][J_TASK].pop(J_IN)
        task[J_MOD][J_TASK][J_REQUEST] = {}
        task[J_MOD][J_TASK][J_REQUEST]['user_id'] = catch_user_id()
        task[J_MOD][J_TASK][J_REQUEST]['app_name'] = dname
        task[J_MOD][J_TASK][J_REQUEST]['ip'] = v['ip']
        task[J_MOD][J_TASK][J_REQUEST]['hostname'] = v['hostname']
        task[J_MOD][J_TASK][J_REQUEST]['rt_inspect'] = v['rt_inspect']
        task[J_MOD][J_TASK][J_REQUEST]['cur_engine_ver'] = v['cur_engine_ver']
        data_center.module_request(task, mustbedata=False)
    else:
        AgentLog.get_logger().error(app_resp_string)

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST
    
#-----------------------------------------------------------------------
def proc_app_log(fname_prefix, seek_path, log_type, today, logs):
    """
    proc app log
    """

    try:
        if os.path.exists(seek_path):
            with open(seek_path, 'r') as f:
                date_src, n = f.read().strip().split(':')
                fday = datetime.datetime.strptime(date_src, '%Y-%m-%d')
                fpos = int(n)
        else:
            fday = today
            fpos = 0
        diffdays = (today - fday).days + 1

        if diffdays < 0:
            #what happened?
            diffdays = 1
            fday = today
            fpos = 0
        
        to_save_fday = None
        to_save_fpos = None
        logs_len = 0
        esc = False
        for d in range(diffdays): 
            fname = '{}-{}-{:02d}-{:02d}.log'.format(
                                                    fname_prefix,
                                                    fday.year, 
                                                    fday.month, 
                                                    fday.day)

            if not os.path.exists(fname):
                fday = fday + datetime.timedelta(days=1)
                fpos = 0
                continue

            with open(fname, 'r') as f:
                f.seek(fpos)
                for l in f.readlines():
                    l_real_len = len(l.encode('utf8'))

                    l = l.strip()
                    if not l:
                        continue

                    logs.append('{},{}'.format(log_type, l))
                    fpos += l_real_len
                    logs_len += l_real_len
                    to_save_fday = fday
                    to_save_fpos = fpos
                    if logs_len > LSF_MAX_APP_LOG_SIZE:
                        esc = True
                        break
            if esc:
                break

            fday = fday + datetime.timedelta(days=1)
            fpos = 0

        seek_info = ''
        if logs_len > 0:
            seek_info = '{}:{}'.format(to_save_fday.strftime('%Y-%m-%d'), to_save_fpos)
            
        return logs_len, seek_info
    except:
        AgentLog.get_logger().error(agent_format_exc())
        return 0, ''

def task_app_log(task, data_center):
    """
    app_log
    """

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

    APP_LOG_PATH = '/var/log/gooroom-lsf'
    if not os.path.isdir(APP_LOG_PATH):
        os.makedirs(APP_LOG_PATH)
        return

    AHNLAB_LOG_PATH = '/var/log/gooroom-lsf/kr.gooroom.ahnlab.v3'
    if not os.path.exists(AHNLAB_LOG_PATH):
        return

    MSEEK_PATH = '/var/tmp/gooroom-agent-service/ahnlab_log_mal_seek'
    ESEEK_PATH = '/var/tmp/gooroom-agent-service/ahnlab_log_event_seek'
    today = datetime.datetime.now()
    logs = []
    mlen, mseekinfo = proc_app_log(AHNLAB_LOG_PATH+'/ahnlab-v3-malware',
                        MSEEK_PATH,
                        'malcode',
                        today,
                        logs)
    elen, eseekinfo = proc_app_log(AHNLAB_LOG_PATH+'/ahnlab-v3-event',
                        ESEEK_PATH,
                        'update',
                        today,
                        logs)

    if elen + mlen > 0:
        task[J_MOD][J_TASK].pop(J_IN)
        task[J_MOD][J_TASK][J_REQUEST] = {}
        task[J_MOD][J_TASK][J_REQUEST]['user_id'] = catch_user_id()
        task[J_MOD][J_TASK][J_REQUEST]['app_name'] = 'kr.gooroom.ahnlab.v3'
        task[J_MOD][J_TASK][J_REQUEST]['logs'] = logs
        data_center.module_request(task, mustbedata=False)

        if mlen > 0:
            with open(MSEEK_PATH, 'w') as mf:
                mf.write(mseekinfo)

        if elen > 0:
            with open(ESEEK_PATH, 'w') as ef:
                ef.write(eseekinfo)

#-----------------------------------------------------------------------
def pick_entrypoint_file():
    """
    pick browser url logfile to be entrypoint
    """

    URL_PATH = \
        AgentConfig.get_config().get('BROWSER_URL', 'URL_PATH')
    if not os.path.exists(URL_PATH):
        return None

    file_list = []
    min_dt = 99991231
    min_idx = -1
    offset = 0
    for url_file in glob.glob(URL_PATH+'/*'):
        if os.path.getsize(url_file) == 0:
            continue
        dt = int(url_file.split('-')[-1])
        if dt < min_dt:
            min_dt = dt
            min_idx = offset
        file_list.append(url_file)
        offset += 1

    if min_idx == -1:
        return None

    AgentLog.get_logger().info('pick entrypoint {}'.format(file_list[min_idx]))

    return file_list[min_idx]

def pick_next_file(current_filename):
    """
    pick next date file
    """

    URL_PATH = \
        AgentConfig.get_config().get('BROWSER_URL', 'URL_PATH')
    if not os.path.exists(URL_PATH):
        return None

    current_dt = int(current_filename.split('-')[-1])
    for url_file in glob.glob(URL_PATH+'/*'):
        if os.path.getsize(url_file) == 0:
            continue
        dt = int(url_file.split('-')[-1])
        if dt > current_dt:
            AgentLog.get_logger().info('pick next {}'.format(url_file))
            return url_file

    return None

def task_browser_url(task, data_center):
    """
    browser url
    """

    '''
    if data_center.visa_status != VISA_STATUS_APPROVED:
        task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST
        return
    '''

    AGENT_OWN_DIR = \
        AgentConfig.get_config().get('MAIN', 'AGENT_OWN_DIR')

    fname = linenum = None

    URL_TAILED = AGENT_OWN_DIR + '/browser_url_tailed'
    if os.path.exists(URL_TAILED):
        try:
            with open(URL_TAILED, 'r') as f:
                fname, linenum = f.read().strip('\n').split(',')
                linenum = int(linenum)
            if not os.path.exists(fname):
                fname = pick_next_file(fname)
                linenum = 0
                if not fname:
                    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST
                    return
        except:
            e = agent_format_exc()
            AgentLog.get_logger().info(e)

            fname = pick_entrypoint_file()
            linenum = 0
            if not fname:
                task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST
                return
    else:
        fname = pick_entrypoint_file()
        linenum = 0
        if not fname:
            task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST
            return
     
    TRANSMIT_URL_NUM = \
        AgentConfig.get_config().get('BROWSER_URL', 'TRANSMIT_URL_NUM')
    MAX_URL_SIZE = \
        AgentConfig.get_config().get('BROWSER_URL', 'MAX_URL_SIZE')

    with open(fname, 'r') as f:
        lines = f.readlines() 

    if len(lines) == linenum:
        fname = pick_next_file(fname)
        linenum = 0
        if not fname:
            task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST
            return

        with open(fname, 'r') as f:
            lines = f.readlines()

    logs = []
    offset = 0
    for line in lines[linenum:]:
        if offset >= TRANSMIT_URL_NUM:
            break
        splited = line.split(']')
        lg = '{},{},{},{}'.format(
                '1111-11-11 11:11:11',
                'SARABAL', 
                '0', 
                ' '.join(splited[3:]))
        logs.append(lg)
        offset += 1
    linenum += offset

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {}
    task[J_MOD][J_TASK][J_REQUEST]['logs'] =  logs
    data_center.module_request(task, mustbedata=False)

    with open(URL_TAILED, 'w') as f:
        f.write('{},{}'.format(fname, linenum))
        
    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

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
    
    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_security_log(task, data_center):
    """
    load security log on journal
    """

    disk_usage = agentdir_usage()
    if disk_usage >= 99:
        task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST
        AgentLog.get_logger().error('agent disk full')
        return

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
                task[J_MOD][J_TASK][J_REQUEST]['user_id'] = catch_user_id()
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
    send_journallog(lg, JOURNAL_INFO, gc)

#-----------------------------------------------------------------------
def get_arp_list():
    """
    arp list
    """

    arp_list = []

    with open('/proc/net/arp') as f:
        for line in f.readlines():
            splited =  line.split()
            if len(splited) != 6:
                continue
            ip = splited[0].strip()
            try:
                it = ipaddress.ip_address(ip)
                if isinstance(it, ipaddress.IPv4Address):
                    mac = splited[3].strip()
                    arp_list.append('{}-{}'.format(ip, mac))
            except:
                pass

    return arp_list

def get_arp_list_deprecated():
    """
    arp list
    """

    pp = subprocess.Popen(
        ['/usr/bin/arp-scan', '--localnet'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    sout, serr = pp.communicate()

    if pp.returncode != 0:
        raise Exception('arp-scan returns !0')

    sout = sout.decode('utf8')

    records = sout.split('\n')
    arp_list = []
    for record in records:
        splited = record.split()
        try:
            it = ipaddress.ip_address(splited[0])
            if isinstance(it, ipaddress.IPv4Address):
                arp_list.append('{}-{}'.format(splited[0], splited[1]))
        except:
            pass

    return arp_list

def get_mac_for_ip(ip):
    """
    mac for ip
    """
    
    ifaces = netifaces.interfaces()
    for iface in ifaces:
        addrs = netifaces.ifaddresses(iface)
        if ip == addrs[netifaces.AF_INET][0]['addr']:
            return addrs[netifaces.AF_PACKET][0]['addr']

    return ''
    
def task_sched_info(task, data_center):
    """
    arp list
    """

    ip = remote_ipaddress()
    mac = get_mac_for_ip(ip)
    arp_list = get_arp_list()
    
    task[J_MOD][J_TASK][J_OUT]['local_ip'] = ip
    task[J_MOD][J_TASK][J_OUT]['mac'] = mac
    task[J_MOD][J_TASK][J_OUT]['arp_list'] = ','.join(arp_list)
    
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
        AgentLog.get_logger().info(agent_format_exc())
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
            AgentLog.get_logger().info(serr)
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
        AgentLog.get_logger().info(agent_format_exc())
        return -1, -1

#-----------------------------------------------------------------------
def agentdir_usage():
    """
    get agent directory usage
    """

    try:
        p = subprocess.Popen(
            ['df', '-B1', '/var/tmp'], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE)

        sout, serr = p.communicate()
        if serr:
            AgentLog.get_logger().info(serr)
            return 0

        sout = sout.decode('utf8')
        infos = [l.split() for l in sout.split('\n')]

        for info in infos:
            if len(info) < 6:
                continue
            usage = info[4].strip()[:-1]
            if not usage.isdigit():
                continue
            return int(usage)
        else:
            return 0
    except:
        AgentLog.get_logger().info(agent_format_exc())
        return 0
