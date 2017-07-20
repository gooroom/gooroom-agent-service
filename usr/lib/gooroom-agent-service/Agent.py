#! /usr/bin/env python3

#-----------------------------------------------------------------------
import os
import sys
import dbus
import dbus.service
import time
import multiprocessing
import simplejson as json
import traceback
import OpenSSL

from gi.repository import GLib
from dbus.mainloop.glib import DBusGMainLoop

from agent_define import AGENT_OK,AGENT_NOK
from agent_util import AgentLog,AgentConfig
from agent_clientjob_dispatcher import AgentClientJobDispatcher
from agent_serverjob_dispatcher import AgentServerJobDispatcher
from agent_data_center import AgentDataCenter

#-----------------------------------------------------------------------
#for decorator parameter
DBUS_NAME = AgentConfig.get_config().get('MAIN', 'DBUS_NAME')
DBUS_OBJ = AgentConfig.get_config().get('MAIN', 'DBUS_OBJ')
DBUS_IFACE = AgentConfig.get_config().get('MAIN', 'DBUS_IFACE')

#-----------------------------------------------------------------------
class Agent(dbus.service.Object):
    """
    |AGENT|
    """

    def __init__(self):

        self.logger = AgentLog.get_logger()

        #DBUS
        DBusGMainLoop(set_as_default=True)
        self._loop = None
        self._loop = GLib.MainLoop()

        busname = dbus.service.BusName(DBUS_NAME, bus=dbus.SystemBus())
        dbus.service.Object.__init__(self, busname, DBUS_OBJ)

        #SERVERJOB_DISPATCHER
        self.server_dispatcher = None
        #CLIENTJOB_DISPATCHER
        self.client_dispatcher = None

        self.logger.info('AGENT CREATED')

    def __del__(self):
        self.logger.debug('AGENT DESTROYED')

    def run(self):
        """
        AGENT's main loop
        """

        self.logger.info('AGENT RUNNING')

        self.data_center = AgentDataCenter()
        
        #CLIENT-JOB DISPATCHER
        self.client_dispatcher = AgentClientJobDispatcher(self.data_center)
        self.client_dispatcher.start()

        #SERVER-JOB DISPATCHER
        self.server_dispatcher = AgentServerJobDispatcher(self.data_center)
        self.server_dispatcher.start()

        self._loop.run()

        self.logger.info('AGENT QUIT')

    @dbus.service.method(DBUS_IFACE, sender_keyword='sender', in_signature='v', out_signature='v')
    def do_task(self, args, sender=None):
        """
        app, daemon 등에서 전송한 client job을 수행

        self.get_sender_pid(sender)
        """
        
        try:
            self.logger.info('DBUS CLIENTJOB -> %s' % args)
            task = json.loads(args)
            ret = json.dumps(self.client_dispatcher.dbus_do_task(task))
            self.logger.info('DBUS CLIENTJOB <- %s' % ret)
            return ret

        except: 
            e = traceback.format_exc()
            AgentLog.get_logger().error(e)

            return args
        
    @dbus.service.method(DBUS_IFACE)
    def stop(self, args):
        """
        dbus stop
        """

        try:
            self.logger.info('AGENT STOPPING BY DBUS')

            #dispatcher 중지한 후
            if self.server_dispatcher:
                self.server_dispatcher.down()

            if self.client_dispatcher:
                self.client_dispatcher.down()

            #agent 중지
            if self._loop and self._loop.is_running():
                self._loop.quit()

            self.logger.info('AGENT STOPPED BY DBUS')
        except:
            m = traceback.format_exc()
            self.logger.error(m)
            return m

        return AGENT_OK

    @classmethod
    def stop_myself(cls, target):
        """
        stop myself
        """

        system_bus = dbus.SystemBus()

        bus_object = system_bus.get_object(DBUS_NAME, DBUS_OBJ)
            
        bus_interface = dbus.Interface(bus_object, dbus_interface=DBUS_IFACE)

        return eval('bus_interface.stop(target)')
        
    @dbus.service.method(DBUS_IFACE)
    def reload(self, args):
        """
        reload
        """

        try:
            self.logger.info('AGENT RELOADING BY DBUS')
            self.data_center.show()
            self.logger.info('AGENT RELOADED BY DBUS')
        except:
            m = traceback.format_exc()
            self.logger.error(m)
            return m

        return AGENT_OK

    @classmethod
    def reload_myself(cls, target):
        """
        stop myself
        """

        system_bus = dbus.SystemBus()

        bus_object = system_bus.get_object(DBUS_NAME, DBUS_OBJ)
            
        bus_interface = dbus.Interface(bus_object, dbus_interface=DBUS_IFACE)

        return eval('bus_interface.reload(target)')
        
    def get_sender_pid(self, sender):
        """
        get sender's pid
        """

        pid = -1

        try:
            bus_object = dbus.SystemBus().get_object(
                'org.freedesktop.DBus', '/org/freedesktop/DBus')#DBUS_NAME, DBUS_OBJ)
            bus_interface = dbus.Interface(
                bus_object, dbus_interface='org.freedesktop.DBus')#DBUS_IFACE)
            pid = bus_interface.GetConnectionUnixProcessID(sender)

        except:
            AgentLog.get_logger().error('(do_task) %s' % traceback.format_exc())

        return pid

#-----------------------------------------------------------------------
if __name__ == '__main__':
    """
    main
    """

    #stop for systemd
    if len(sys.argv) > 1 and sys.argv[1] == 'stop':
        Agent.stop_myself('')
        sys.exit(0)

    #reload for systemd
    if len(sys.argv) > 1 and sys.argv[1] == 'reload':
        Agent.reload_myself('')
        sys.exit(0)

    me = None
    try:
        me = Agent()
        me.run()

    except:
        AgentLog.get_logger().error('(main) %s' % traceback.format_exc())

        if me:
            me.stop('')
        raise
    
