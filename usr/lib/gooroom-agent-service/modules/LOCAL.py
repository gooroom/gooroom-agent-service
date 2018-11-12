#! /usr/bin/env python3

#-----------------------------------------------------------------------
import subprocess
import pathlib
import struct
import psutil
import shutil
import glob
import os

from agent_util import AgentConfig,AgentLog,agent_format_exc
from agent_define import *

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
def task_delete_homefolder(task, data_center):
    """
    delete_homefolder
    """

    if data_center.home_folder_delete_flag[0] == False:
        task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST
        return
        
    #로컬에 존재하는 온라인계정
    with open('/etc/passwd') as f:
        pws = f.readlines()

    online_accounts = []
    for pw in pws:
        splited = pw.split(':')
        if 'gooroom-online-account' in splited[4]:
            online_accounts.append(splited[0])

    #현재 로그인한 계정
    with open('/var/run/utmp', 'rb') as f:
        fc = memoryview(f.read())

    utmp_fmt = '<ii32s4s32s'
    user_id = '-'

    logined_accounts = []
    for i in range(int(len(fc)/384)):
        ut_type, ut_pid, ut_line, ut_id, ut_user = \
            struct.unpack(utmp_fmt, fc[384*i:76+(384*i)])
        ut_line = ut_line.decode('utf8').strip('\00')
        ut_id = ut_id.decode('utf8').strip('\00')

        if ut_type == 7 and ut_id == ':0':
            logined_accounts.append(ut_user.decode('utf8').strip('\00'))

    #로컬에 존재하는 온라인계정이 로그인 중이 아니라면 삭제 절차
    for online_account in online_accounts:
        if not online_account in logined_accounts:
            AgentLog.get_logger().info('deleting {}'.format(online_account))

            #이전에 로그인한 계정의 프로세스가 살아 있는 경우가 있기때문에
            #삭제할 계정의 프로세스가 있다면 강제종료
            for proc in psutil.process_iter():
                if proc.username() == online_account:
                    pid = str(proc.pid)
                    kill_cmd = subprocess.Popen(
                                            ['kill', '-9', pid], 
                                            stdout=subprocess.PIPE)
                    kill_out = kill_cmd.communicate()[0]
                    if kill_cmd.returncode != 0:
                        raise Exception(
                            'failed to kill pid({})={}'.format(
                                                            proc.pid, 
                                                            kill_out))
                    AgentLog.get_logger().info('killed process({})'.format(pid))

            #ecryptfs umount:로그아웃 시 ecryptfs-umount-private 실패를 고려해서
            #ecryptfs-umount-private를 결과와 상관없이 한 번 실행
            umount_cmd = subprocess.Popen(
                ['sudo', 
                '-u', 
                online_account, 
                '/usr/bin/ecryptfs-umount-private'],
                stdout=subprocess.PIPE)
            umount_out, umount_err = umount_cmd.communicate()
            AgentLog.get_logger().info(
                'ecryptfs umount={} {}'.format(umount_out, umount_err))

            #shield
            encrypted_fname = 'Access-Your-Private-Data.desktop'
            if not os.path.isfile(
                '/home/{}/{}'.format(online_account, encrypted_fname)):
                raise Exception(
                    '{} not found in /home/{}'.format(encrypted_fname, online_account))
                
            #클라우드에 마운트되어있는 데이터를 보호하기 위해서
            #홈디렉토리에 마운트되어 있는 것들을 존재한다면 마운트해제
            for fn in os.listdir('/home/{}'.format(online_account)):
                mounted = os.path.ismount(fn)

                if mounted:
                    umount_cmd = subprocess.Popen(
                                            ['umount', fn], 
                                            stdout=subprocess.PIPE)
                    umount_out = umount_cmd.communicate()[0]
                    if umount_cmd.returncode != 0:
                        raise Exception(
                            'failed to umount({})={}'.format(
                                                        fn, 
                                                        umount_out))
                    AgentLog.get_logger().info('umounted ({})'.format(fn))

            #계정삭제
            deluser_cmd = subprocess.Popen(
                ['deluser', '--remove-home', 
                online_account], 
                stdout=subprocess.PIPE)
            deluser_out, deluser_err = deluser_cmd.communicate()
            if deluser_cmd.returncode != 0:
                raise Exception(
                    'failed to deluser({})={} {}'.format(
                                                online_account, 
                                                deluser_out,
                                                deluser_err))
            AgentLog.get_logger().info('deleted ({})'.format(online_account))

            #ecryptfs 디렉토리 삭제
            #ecryptfs_dir = '/home/.ecryptfs/{}'.format(online_account)
            #shutil.rmtree(ecryptfs_dir)

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST
