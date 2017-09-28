#! /usr/bin/env python3

#-----------------------------------------------------------------------
import dbus
import time

from agent_util import AgentLog,AgentConfig,agent_format_exc
from agent_define import *

#-----------------------------------------------------------------------
g_conf = AgentConfig.get_config()

SD_BUS_NAME = 'org.freedesktop.systemd1'
SD_BUS_OBJ = '/org/freedesktop/systemd1'
SD_BUS_IFACE = 'org.freedesktop.systemd1.Manager'
SD_BUS_PROP='org.freedesktop.DBus.Properties'
SD_BUS_UNIT='org.freedesktop.systemd1.Unit'

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
def task_daemon_status(task, data_center):
    """
    systemctl status service
    """

    service = task[J_MOD][J_TASK][J_IN]['service']

    bus = dbus.SystemBus()
    systemd1 = bus.get_object(SD_BUS_NAME, SD_BUS_OBJ)
    manager = dbus.Interface(systemd1, dbus_interface=SD_BUS_IFACE)

    daemon_status = \
        ','.join(str(state) for state in service_state(bus, manager, service, all_state=True)) 
    task[J_MOD][J_TASK][J_OUT]['daemon_status'] = daemon_status

#-----------------------------------------------------------------------
def dum_func(operation):
    """
    until finding dbus method
    """

    ORG = '/run/systemd/generator.late/gop-daemon.service'
    TARGET1 = '/run/systemd/generator.late/graphical.target.wants/gop-daemon.service'
    TARGET2 = '/run/systemd/generator.late/multi-user.target.wants/gop-daemon.service'

    import os

    if operation == 'enable':
        if not os.path.isfile(TARGET1):
            os.symlink(ORG, TARGET1)
        if not os.path.isfile(TARGET2):
            os.symlink(ORG, TARGET2)
    else:
        if os.path.isfile(TARGET1):
            os.remove(TARGET1)
        if os.path.isfile(TARGET2):
            os.remove(TARGET2)

def task_daemon_able(task, data_center):
    """
    systemctl enable/disable service
    """

    service = task[J_MOD][J_TASK][J_IN]['service']
    operation = task[J_MOD][J_TASK][J_IN]['operation']

    bus = dbus.SystemBus()
    systemd1 = bus.get_object(SD_BUS_NAME, SD_BUS_OBJ)
    manager = dbus.Interface(systemd1, dbus_interface=SD_BUS_IFACE)

    if service == 'gop-daemon.service':
        dum_func(operation)
    else:
        if operation == 'enable':
            manager.EnableUnitFiles([service], False, False)
        else:
            manager.DisableUnitFiles([service], False)
    manager.Reload()

#-----------------------------------------------------------------------
def task_daemon_start(task, data_center):
    """
    systemctl start service
    """

    service = task[J_MOD][J_TASK][J_IN]['service']

    bus = dbus.SystemBus()
    systemd1 = bus.get_object(SD_BUS_NAME, SD_BUS_OBJ)
    manager = dbus.Interface(systemd1, dbus_interface=SD_BUS_IFACE)

    manager.StartUnit(service, "fail")

    return wait_status_updated(bus, manager, service, 'active', 10)

#-----------------------------------------------------------------------
def task_daemon_stop(task, data_center):
    """
    systemctl start service
    """

    service = task[J_MOD][J_TASK][J_IN]['service']

    bus = dbus.SystemBus()
    systemd1 = bus.get_object(SD_BUS_NAME, SD_BUS_OBJ)
    manager = dbus.Interface(systemd1, SD_BUS_IFACE)

    manager.StopUnit(service, "fail")

    return wait_status_updated(bus, manager, service, 'inactive', 10)

#-----------------------------------------------------------------------
def task_daemon_restart(task, data_center):
    """
    systemctl start service
    """

    service = task[J_MOD][J_TASK][J_IN]['service']

    bus = dbus.SystemBus()
    systemd1 = bus.get_object(SD_BUS_NAME, SD_BUS_OBJ)
    manager = dbus.Interface(systemd1, SD_BUS_IFACE)

    manager.RestartUnit(service, "fail")

    return wait_status_updated(bus, manager, service, 'active', 10)

#-----------------------------------------------------------------------
def task_daemon_reload(task, data_center):
    """
    systemctl reload service
    """

    service = task[J_MOD][J_TASK][J_IN]['service']

    bus = dbus.SystemBus()
    systemd1 = bus.get_object(SD_BUS_NAME, SD_BUS_OBJ)
    manager = dbus.Interface(systemd1, SD_BUS_IFACE)

    manager.ReloadUnit(service, "fail")

    return wait_status_updated(bus, manager, service, 'active', 10)

#-----------------------------------------------------------------------
def service_state(bus, manager, service, all_state=False):
    """
    systemctl status service
    """

    unit = manager.GetUnit(service)
    unit_obj = bus.get_object(SD_BUS_NAME, unit)
    unit_prop = dbus.Interface(unit_obj, SD_BUS_PROP)

    active = unit_prop.Get(SD_BUS_UNIT, 'ActiveState')

    if not all_state:
        return (active,)

    #for task_daemon_status
    sub = None
    load = None

    sub = unit_prop.Get('org.freedesktop.systemd1.Unit', 'SubState')
    load = unit_prop.Get('org.freedesktop.systemd1.Unit', 'LoadState')

    can_start = unit_prop.Get('org.freedesktop.systemd1.Unit', 'CanStart')
    can_stop = unit_prop.Get('org.freedesktop.systemd1.Unit', 'CanStop')
    can_reload = unit_prop.Get('org.freedesktop.systemd1.Unit', 'CanReload')

    return (active,sub,load,can_start,can_stop,can_reload)

#-----------------------------------------------------------------------
def wait_status_updated(bus, manager, service, status, timeout):
    """
    action 후에 daemon 상태가 timeout기간동안
    정상적으로 변경이 되는 지 확인
    """

    for i in range(timeout):
        if service_state(bus, manager, service)[0] == status:
            return 'OK'

        time.sleep(1)

    #return 'TIMEOUT'
    raise Exception('SYSTEMD TIMEOUT')

