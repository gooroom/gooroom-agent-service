#! /usr/bin/env python3

#-----------------------------------------------------------------------
import simplejson as json
import dbus.service
import dbus
import sys

from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

from agent_clientjob_dispatcher import AgentClientJobDispatcher
from agent_serverjob_dispatcher import AgentServerJobDispatcher
from agent_util import AgentLog,AgentConfig,agent_format_exc
from agent_data_center import AgentDataCenter
from agent_define import *
from agent_lsf import *

#-----------------------------------------------------------------------
#for decorator parameter
DBUS_NAME = AgentConfig.get_config().get('MAIN', 'DBUS_NAME')
DBUS_OBJ = AgentConfig.get_config().get('MAIN', 'DBUS_OBJ')
DBUS_IFACE = AgentConfig.get_config().get('MAIN', 'DBUS_IFACE')

#-----------------------------------------------------------------------
class Agent(dbus.service.Object):
    """
    |AGENT.|
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

    def run(self):
        """
        AGENT's main loop
        """

        self.logger.info('AGENT RUNNING')

        #DATA CENTER
        self.data_center = AgentDataCenter(self)
        
        #CLIENT-JOB DISPATCHER
        self.client_dispatcher = AgentClientJobDispatcher(self.data_center)
        self.client_dispatcher.start()

        #SERVER-JOB DISPATCHER
        self.server_dispatcher = AgentServerJobDispatcher(self.data_center)
        self.server_dispatcher.start()

        #LOOPING ON
        self._loop.run()

        self.logger.info('AGENT QUIT')

    def watch_process(self, sender):
        """
        protect invoking do_task from unprivileged process
        """

        wps = AgentConfig.get_config().get('SECURITY', 'WHITE_PROCESS').split(',')
        white_process = [wp.split('&&') for wp in wps]

        pid = self.get_sender_pid(sender)

        import psutil
        ps = psutil.Process(pid)
        path = ps.exe()
        cmds = ps.cmdline()

        self.logger.debug('FROM WHOM=%s : %s' % (path, cmds))
        if len(cmds) > 0:
            cmds[0] = path
            self.logger.debug('path -> cmds[0]')

        for wl in white_process:
            if len(wl) <= len(path) and all(x == y for x, y in zip(wl, cmds)):
                return True

        return False

    def watch_task(self, task):
        """
        check whether task is allowed for dbus
        """

        modn = task[J_MOD][J_MODN]
        taskn = task[J_MOD][J_TASK][J_TASKN]

        return (modn, taskn) in self.data_center.dbusable_tasks

    @dbus.service.method(DBUS_IFACE, sender_keyword='sender', in_signature='v', out_signature='v')
    def do_task(self, args, sender=None):
        """
        외부에서 dbus를 통해 전송된 client job을 수행
        """
        
        try:
            self.logger.info('DBUS CLIENTJOB -> %s' % args)

            task = json.loads(args)


            ############ LSF MESSAGE ###########
            if 'seal' in task:
                return self.lsf_processing(task)
            ####################################


            #설정파일에 기재된 화이트리스트를 확인
            #절대경로로 전송자를 인증
            if not self.watch_process(sender):
                task['WARNNING'] = 'You are an unauthenticated process.'
                self.logger.error('!! UNAUTHENTICATED ACCESS !!')
                return json.dumps(task)

            #템플릿에서 dbus 허용이 되어있는 태스크만 허용
            if not self.watch_task(task):
                task['WARNNING'] = 'You are an unauthorized process.'
                self.logger.error('!! UNAUTHORIZED ACCESS !!')
                return json.dumps(task)
                
            #이 태스크는 dbus에서 전송되었음을 worker에게 알림
            task['FROM'] = 'dbus'

            ret = json.dumps(self.client_dispatcher.dbus_do_task(task))
            self.logger.info('DBUS CLIENTJOB <- %s' % ret)
            return ret

        except: 
            e = agent_format_exc()
            AgentLog.get_logger().error(e)

            return args
        
    def lsf_processing(self, task):
        """
        process gooroom security framework message
        """

        try:
            seal = task['seal']
            if seal['glyph'] == LSF_GLYPH_AUTH:
                r = lsf_auth(self.data_center)
                if r != 0:
                    raise Exception('FAIL TO AUTH')
                return

            letter = task['letter']
            dec_m = lsf_dec_msg(self.data_center, letter)
            print('decrypted message={}'.format(dec_m))
        except:
            self.logger.error(agent_format_exc())

    def watch_admin(self, sender):
        """
        """

        pid = self.get_sender_pid(sender)

        with open('/proc/{}/status'.format(pid), 'r') as f:
            for l in f.readlines():
                if l.startswith('Uid:'):
                    if int(l.split()[2]) == 0:
                        return True

        return False

    @dbus.service.method(DBUS_IFACE, sender_keyword='sender')
    def stop(self, args, sender=None):
        """
        dbus stop
        """

        try:
            if not self.watch_admin(sender):
                self.logger.error('!! TRY TO STOP BY NO-ADMIN')
                return

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
            e = agent_format_exc()
            self.logger.error(e)
            return e

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
        
    @dbus.service.method(DBUS_IFACE, sender_keyword='sender')
    def reload(self, args, sender=None):
        """
        reload
        """

        try:
            if not self.watch_admin(sender):
                self.logger.error('!! TRY TO RELOAD BY NO-ADMIN')
                return

            self.logger.info('AGENT RELOADING BY DBUS')
            self.data_center.show()
            self.logger.info('AGENT RELOADED BY DBUS')
        except:
            e = agent_format_exc()
            self.logger.error(e)
            return e

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
                'org.freedesktop.DBus', '/org/freedesktop/DBus')
            bus_interface = dbus.Interface(
                bus_object, dbus_interface='org.freedesktop.DBus')
            pid = bus_interface.GetConnectionUnixProcessID(sender)

        except:
            AgentLog.get_logger().error(agent_format_exc())

        return pid

    @dbus.service.signal(DBUS_IFACE, signature='i')
    def sleep_time(self, tm):
        """
        send signal to user session 
        so as to set sleep_time
        """

        pass

    @dbus.service.signal(DBUS_IFACE, signature='i')
    def dpms_on_x_off(self, tm):
        """
        send signal to user session 
        so as to set dpms_on_ac_off and dpms_on_battery_off
        """

        pass

    @dbus.service.signal(DBUS_IFACE, signature='i')
    def update_operation(self, tm):
        """
        send signal to user session 
        so as to set update-operation
        """

        pass

    @dbus.service.signal(DBUS_IFACE, signature='v')
    def app_black_list(self, tm):
        """
        send signal to user session 
        so as to set app-black-list
        """

        pass

    @dbus.service.signal(DBUS_IFACE, signature='v')
    def set_noti(self, noti):
        """
        send signal to user session 
        so as to set noti
        """

        pass

    @dbus.service.signal(DBUS_IFACE, signature='v')
    def agent_msg(self, msg):
        """
        send signal to user session 
        so as to send agent-msg
        """

        pass

    @dbus.service.signal(DBUS_IFACE, signature='v')
    def controlcenter_items(self, tm):
        """
        send signal to user session 
        so as to set controlcenter-items
        """

        pass

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
        AgentLog.get_logger().error(agent_format_exc())

        if me:
            me.stop('')
        raise
    
