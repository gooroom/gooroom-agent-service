#! /usr/bin/env python3

#-----------------------------------------------------------------------
from datetime import datetime
from systemd import journal
import simplejson as json
import logging.handlers
import configparser
import subprocess
import traceback
import logging
import OpenSSL
import base64
import struct
import time
import dbus
import sys
import os

from agent_error import AgentError
from agent_define import *
from pwd import getpwnam

#-----------------------------------------------------------------------
class AgentConfig:
    """
    agent config
    """
    
    _parsers = {}

    @classmethod
    def get_config(cls, config_fullpath=CONFIG_FULLPATH, reload=False):
        """
        return singleton RawConfigParser
        """

        if not reload and config_fullpath in cls._parsers:
            
            return cls._parsers[config_fullpath]

        if not os.path.exists(config_fullpath):
            raise AgentError(
                'config file(%s) specified' 
                ' in AgentDefine.py does not be found' % config_fullpath)

        parser = configparser.RawConfigParser()
        parser.optionxform = str
        parser.read(config_fullpath)
        cls._parsers[config_fullpath] = parser
        return parser
        
    @classmethod
    def get_my_agentname(cls):
        """
        return agent-name calling this method
        """

        return sys.argv[0].split('/')[-1].split('.')[0]

#-----------------------------------------------------------------------
class AgentLog:
    """
    agent log
    """

    #default logger
    _logger = None

    #named
    _named_logger = {}

    @classmethod
    def get_logger(cls, filename=None):
        """
        return singleton logger
        """

        logger = None

        if filename:
            if filename in cls._named_logger:
                return cls._named_logger[filename]
            else:
                logger = logging.getLogger(filename)
                cls._named_logger[filename] = logger

        else:
            if cls._logger:
                return cls._logger
            else:
                cls._logger = logging.getLogger('AGENT')
                logger = cls._logger

        conf = AgentConfig.get_config()

        #log level
        logger.setLevel(eval('logging.%s' % conf.get('LOG', 'LEVEL')))

        #log path
        log_path = conf.get('LOG', 'PATH')
        if log_path[:-1] != '/':
            log_path += '/'

        #make dirs of log path
        try:
            os.makedirs(log_path)
        except OSError:
            if os.path.exists(log_path):
                pass
            else:
                raise

        #datetime
        today = datetime.now().strftime('%Y%m%d')

        #filename
        if not filename:
            filename = sys.argv[0].split('/')[-1].split('.')[0]

        #log fullpath
        #log_fullpath = '%s%s_%s.log' % (log_path, filename, today)
        log_fullpath = '%s%s.log' % (log_path, filename)

        #max_bytes, backup_count 
        max_bytes = int(conf.get('LOG', 'MAX_BYTES'))
        backup_count = int(conf.get('LOG', 'BACKUP_COUNT'))

        file_handler = logging.handlers.RotatingFileHandler(
            log_fullpath, 
            maxBytes=max_bytes, 
            backupCount=backup_count)

        #formatter
        fmt = logging.Formatter(conf.get('LOG', 'FMT'))
        file_handler.setFormatter(fmt)

        logger.addHandler(file_handler)

        return logger

#-----------------------------------------------------------------------
def agent_format_exc():
    """
    reprlib version of format_exc of traceback
    """

    return '\n'.join(traceback.format_exc().split('\n')[-4:-1])

#-----------------------------------------------------------------------
def catch_user_id():
    """
    get session login id
    (-) not login
    (+user) local user
    (user) remote user
    """

    pp = subprocess.Popen(
        ['loginctl', 'list-sessions'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)

    pp_out, pp_err = pp.communicate()
    pp_out = pp_out.decode('utf8').split('\n')

    for l in pp_out:
        l = l.split()
        if len(l) < 3:
            continue
        try:
            sn = l[0].strip()
            if not sn.isdigit():
                continue
            uid = l[1].strip()
            if not uid.isdigit():
                continue
            user = l[2].strip()
            pp2 = subprocess.Popen(
                ['loginctl', 'show-session', sn],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)

            pp2_out, pp2_err = pp2.communicate()
            pp2_out = pp2_out.decode('utf8').split('\n')
            service_lightdm = False
            state_active = False
            active_yes = False
            for l2 in pp2_out:
                l2 = l2.split('=')
                if len(l2) != 2:
                    continue
                k, v = l2
                k = k.strip()
                v = v.strip()
                if k == 'Id'and v != sn:
                    break
                elif k == 'User'and v != uid:
                    break
                elif k == 'Name' and v != user:
                    break
                elif k == 'Service':
                    if 'lightdm' in v:
                        service_lightdm = True
                    else:
                        break
                elif k == 'State':
                    if v == 'active':
                        state_active = True
                    else:
                        break
                elif k == 'Active':
                    if v == 'yes':
                        active_yes = True

                if service_lightdm and state_active and active_yes:
                    gecos = getpwnam(user).pw_gecos.split(',')
                    if len(gecos) >= 5 and gecos[4] == 'gooroom-account':
                        return user
                    else:
                        return '+{}'.format(user)
        except:
            AgentLog.get_logger().debug(agent_format_exc())

    return '-'

#-----------------------------------------------------------------------
def create_journal_logger():
    """
    create journald logger
    """

    journal_logger = logging.getLogger('gooroom-agent')
    journal_logger.propagate = False
    journal_logger.addHandler(journal.JournalHandler(SYSLOG_IDENTIFIER='gooroom-agent'))
    return journal_logger

#-----------------------------------------------------------------------
def JLOG(grmcode, *args, level=JOURNAL_INFO):
    """
    journal logging wrapper
    """

    lg = ''
    if grmcode == GRMCODE_POLLING_TIME:
        lg = 'set polling time to $({})'.format(*args)
    elif grmcode == GRMCODE_HYPERVISOR:
        lg = 'set hypervisor operation to $({})'.format(*args)
    elif grmcode == GRMCODE_CLIENT_POLICY:
        fn = args[0].split('/')[-1]
        lg = 'set the client policy of $({})'.format(fn)
    elif grmcode == GRMCODE_HOMEFOLDER:
        lg = 'set homefolder operation to $({})'.format(*args)
    elif grmcode == GRMCODE_CLIENT_USER_POLICY:
        fn = args[0].split('/')[-1]
        lg = 'set the client-user policy of $({})'.format(fn)
    elif grmcode == GRMCODE_UPDATER:
        lg = 'set gooroom updater to $({})'.format(*args)
    elif grmcode == GRMCODE_AGENT_CONNECTED:
        lg = 'agent has been connected to server'
    elif grmcode == GRMCODE_AGENT_DISCONNECTED:
        lg = 'agent has been disconneted to server:$({})'.format(*args)
    elif grmcode == GRMCODE_CLIENTJOB_SUCCESS:
        lg = 'clientjob succes:$({})'.format(*args)
    elif grmcode == GRMCODE_CERTIFICATE:
        lg = 'set server ceriticate'
    elif grmcode == GRMCODE_APP_LIST:
        lg = 'set app list'
    elif grmcode == GRMCODE_PUSH_UPDATE:
        lg = 'set push-update to $({})'.format(*args)

    if lg:
        send_journallog(lg, level, grmcode)
            

        
#-----------------------------------------------------------------------
def send_journallog(msg, level, grmcode):
    """
    send log to journald
    """

    journal.send(msg, 
                SYSLOG_IDENTIFIER=AGENT_SYSLOG_IDENTIFIER,
                PRIORITY=level,
                GRMCODE=grmcode)
    
#-----------------------------------------------------------------------
def dpkg_configure_a():
    """
    dpkg --configure -a
    """

    pp = subprocess.Popen(
        ['/usr/bin/dpkg', '--configure', '-a'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    pp.communicate()

def apt_exec(cmd, timeout, pkg, data_center):
    """
    apt-get -y
    """
    
    pp_result = ''
    fullcmd = [
        'env',
        'DEBIAN_FRONTEND=noninteractive',
        'DEBIAN_PRIORITY=critical',
        '/usr/bin/apt-get', '-q', '-y', '-o Dpkg::Option::="--force-confnew"', 
        cmd, 
        *pkg.strip().split()]

    for looping_cnt in range(timeout):
        if not data_center.serverjob_dispatcher_thread_on:
            pp_result = 'agent is shutting down...'
            break

        if looping_cnt % 5 == 0:
            pp = subprocess.Popen(
                fullcmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)

            pp_out, pp_err = pp.communicate()
            pp_out = pp_out.decode('utf8')
            pp_err = pp_err.decode('utf8')

            if pp.returncode != 0:
                pp_result = pp_err
                data_center.logger.error(pp_err)
            else:
                pp_result = 'OK {}:{}'.format(cmd, pkg)
                break
        else:
            time.sleep(1)
    else:
        raise Exception(pp_result)

    return pp_result

#-----------------------------------------------------------------------
def pkcon_exec(cmd, timeout, pkg_list, data_center, profile=None):
    """
    pkcon install -y
    """
    
    pp_result = ''

    for looping_cnt in range(timeout):
        if not data_center.serverjob_dispatcher_thread_on:
            pp_result = 'agent is shutting down...'
            break

        if looping_cnt % 5 == 0:
            pp = subprocess.Popen(
                ['/usr/bin/pkcon', cmd, '-y', '-p'] + pkg_list,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)

            pp_out_list = pp.communicate()[0].decode('utf8').split('\n')
            pp_result_list = []
            for o in pp_out_list:
                if o.startswith('상태') \
                    or o.startswith('백분율') \
                    or o.startswith('트랜잭션') \
                    or o.startswith('Status') \
                    or o.startswith('Percentage') \
                    or o.startswith('Transaction'):
                        continue
                pp_result_list.append(o)

            pp_result = '\n'.join(pp_result_list)

            if pp.returncode != 0:
                if cmd == 'install' and pp.returncode == 4:
                    pp_result = 'agent says:패키지가 이미 설치되어 있습니다'
                    break
                if profile and profile == 'yes':
                    raise
                data_center.logger.error(pp_result)
            else:
                break
        else:
            time.sleep(1)
    else:
        raise Exception(pp_result)

    return pp_result

#-----------------------------------------------------------------------
def verify_signature(signature, data):
    """
    verify file signature
    """

    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, 
        open('/etc/gooroom/agent/server_certificate.crt').read())

    OpenSSL.crypto.verify(cert, 
        base64.b64decode(signature.encode('utf8')), 
        data.encode('utf8'), 'sha256')

#-----------------------------------------------------------------------
DBUS_NAME = 'kr.gooroom.agent'
DBUS_OBJ = '/kr/gooroom/agent'
DBUS_IFACE = 'kr.gooroom.agent'

def do_task(task):
    """
    stop myself
    """

    system_bus = dbus.SystemBus()
    bus_object = system_bus.get_object(DBUS_NAME, DBUS_OBJ)
    bus_interface = dbus.Interface(bus_object, dbus_interface=DBUS_IFACE)
    return bus_interface.do_debug(task)

#-----------------------------------------------------------------------
def shell_cmd(cmd_and_arg_list):
    """
    execute shell command
    """

    pp_result = ''
    pp = subprocess.Popen(cmd_and_arg_list,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)

    pp_out, pp_err = pp.communicate()
    pp_out = pp_out.decode('utf8')
    pp_err = pp_err.decode('utf8')

    if pp.returncode != 0:
        raise Exception('{} => {}'.format(cmd_and_arg_list, pp_err))
    return '{} => {}'.format(cmd_and_arg_list, pp_out)
