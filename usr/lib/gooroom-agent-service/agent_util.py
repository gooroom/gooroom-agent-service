#! /usr/bin/env python3

#-----------------------------------------------------------------------
from datetime import datetime
from systemd import journal
import simplejson as json
from pwd import getpwnam
import logging.handlers
import configparser
import traceback
import logging
import struct
import dbus
import sys
import os

from agent_error import AgentError
from agent_define import *

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
                ps = '/var/run/user/%d/gooroom/.grm-user'  % getpwnam(user_id).pw_uid
                #user_id is a local account
                if not 'gooroom-online-account' in splited[4] or not os.path.exists(ps):
                    user_id = '+' + user_id
                break
        else:
            raise Exception('user_id(%s) does not existed in /etc/passwd')

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
