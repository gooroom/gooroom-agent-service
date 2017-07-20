#! /usr/bin/env python3

#-----------------------------------------------------------------------
import os
import sys
import simplejson as json

from agent_error import AgentError

#-----------------------------------------------------------------------
import configparser

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
import logging
import logging.handlers

from datetime import datetime

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
import dbus

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
