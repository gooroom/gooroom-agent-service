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
        log_fullpath = '%s%s_%s.log' % (log_path, filename, today)

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
    read current logined user_id from /var/run/utmp
    """

    with open('/var/run/utmp', 'rb') as f:
        fc = memoryview(f.read())

    utmp_fmt = '<ii32s4s32s'
    user_id = '-'

    for i in range(int(len(fc)/384)):
        ut_type, ut_pid, ut_line, ut_id, ut_user = \
            struct.unpack(utmp_fmt, fc[384*i:76+(384*i)])
        ut_line = ut_line.decode('utf8').strip('\00')
        ut_id = ut_id.decode('utf8').strip('\00')

        if ut_type == 7 and ut_id == ':0':
            user_id = ut_user.decode('utf8').strip('\00')

    #check if user_id is an online account
    with open('/etc/passwd') as f:
        pws = f.readlines()

    if user_id != '-':
        for pw in pws:
            splited = pw.split(':')
            if splited[0] == user_id:
                #ps = '/var/run/user/%d/gooroom/.grm-user'  % getpwnam(user_id).pw_uid
                #user_id is a local account
                if not 'gooroom-online-account' in splited[4]: #or not os.path.exists(ps):
                    user_id = '+' + user_id
                break
        else:
            raise Exception('user_id({}) does not existed in /etc/passwd'.format(user_id))

    return user_id

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
def send_journallog(msg, level, grmcode):
    """
    send log to journald
    """

    journal.send(msg, 
                SYSLOG_IDENTIFIER=AGENT_SYSLOG_IDENTIFIER,
                PRIORITY=level,
                GRMCODE=grmcode)
    
#-----------------------------------------------------------------------
def pkcon_exec(cmd, timeout, pkg_list, data_center):
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

