#! /usr/bin/env python3

#-----------------------------------------------------------------------
import simplejson as json
import multiprocessing
import threading
import importlib
import ctypes
import queue
import time
import glob
import sys
import re

from ctypes import util
from socket import timeout as SOCKET_TIMEOUT

from agent_util import AgentConfig,AgentLog,agent_format_exc,JLOG
from agent_util import send_journallog
from agent_define import *

#-----------------------------------------------------------------------
class AgentJobManager:
    """
    job manager
    """

    def __init__(self, role, data_center):

        self.conf = AgentConfig.get_config()
        self.logger = AgentLog.get_logger()

        self.data_center = data_center
        self.role = role

        self.workers = []

    def put_job(self, job):
        """
        put job
        """

        Q = None
        if self.role == SERVERJOB:
            Q = self.data_center.serverjob_Q
        else:
            Q = self.data_center.clientjob_Q
            
        try:
            #Q가 꽉 찼으면 서버에 더 이상 요청하지 말고 일단 대기
            #clientjob 역시 더 이상 스케쥴링하지 말고 대기
            while True:
                if Q.full():
                    self.logger.error('!! JOB-Q is full')
                    time.sleep(1)
                else:
                    break

            #JOB을 받을 수 있는 상태의 worker만 픽업
            self.workers = \
                [worker for worker in self.workers if worker.alive() and not worker.retiring()]

            worker_num = len(self.workers)

            #worker가 없으면 뽑고
            if worker_num == 0:
                wk = AgentJobWorker(self.role, self.data_center)
                self.workers.append(wk)
                wk.daemon = True
                wk.start()
            #worker가 부족하면 또 뽑고
            else:
                if worker_num < self.data_center.job_max_worker_num \
                    and Q.qsize() > \
                        self.data_center.job_num_per_worker * worker_num:
                    wk = AgentJobWorker(self.role, self.data_center)
                    self.workers.append(wk)
                    wk.daemon = True
                    wk.start()
                        
            Q.put(job)

        except:
            self.logger.error(agent_format_exc())
        
    def allkill(self):
        """
        WORKER를 모두 해고함
        """

        #설정파일에 기재된 시간이 지나면 worker는 자동으로 
        #종료되기 때문에 수동으로 종료시킬 필요가 없음

        pass

#-----------------------------------------------------------------------
class AgentJobWorker(threading.Thread):
    """
    AgentJobWorker
    """

    def __init__(self, role, data_center):

        threading.Thread.__init__(self)

        self.conf = AgentConfig.get_config()
        self.logger = AgentLog.get_logger()

        self.role = role

        self.data_center = data_center

        self.daemon = True

        self.logger.info('A WORKER(%s) EMPLOYED' % self.role)

    def do_task(self, task):
        """
        do task
        """

        module_name = task[J_MOD][J_MODN]
        task_name = task[J_MOD][J_TASK][J_TASKN]

        module = self.data_center.modules[module_name]
        do_task = getattr(module, 'do_task')
        self.logger.info('DOING TASK(%s)' % task_name)

        rsp = None

        #c module
        if type(module) is ctypes.CDLL:
            req = ctypes.c_char_p(json.dumps(task).encode('utf-8'))
            rsp = do_task(req)
            value = ctypes.cast(rsp, ctypes.c_char_p).value.decode('utf-8')
            rsp = json.loads(value)
            self._libc.free(rsp)

        #python module
        else:
            rsp = do_task(task, self.data_center)

        self.logger.info('DONE TASK(%s)' % task_name)
        return rsp

    def make_outtask(self, task, status, err_reason):
        if J_IN in task[J_MOD][J_TASK]:
            task[J_MOD][J_TASK].pop(J_IN)
        if J_REQUEST in task[J_MOD][J_TASK]:
            task[J_MOD][J_TASK].pop(J_REQUEST)
        if J_RESPONSE in task[J_MOD][J_TASK]:
            task[J_MOD][J_TASK].pop(J_RESPONSE)

        task[J_MOD][J_TASK][J_OUT] = {J_STATUS:status, J_MESSAGE:err_reason}
        return task

    def do_clientjob(self, task):
        """
        do clientjob
        """

        try:
            task_name = task[J_MOD][J_TASK][J_TASKN]

            #call module
            task_rsp =  self.do_task(task)

            #error
            m = '[CLIENT FIN] ({:<8}) ({:<30}) {}'.format('no shoot', task_name, task_rsp)
            if task_rsp[J_MOD][J_TASK][J_OUT][J_STATUS] != AGENT_OK: 
                self.logger.error(m)
                return task_rsp

            #if module do not need to request to server, 
            if task_rsp[J_MOD][J_TASK][J_OUT][J_MESSAGE] == SKEEP_SERVER_REQUEST:
                task_rsp[J_MOD][J_TASK][J_OUT][J_MESSAGE] = AGENT_DEFAULT_MESSAGE
                self.logger.debug(m)
                return task_rsp

            #do_task modulates task and returns task.
            #therefore task_rsp is task.
            task = task_rsp

            #shoot
            server_rsp, status_code, err_msg = self.data_center.clientjob_request(task)
            m = '[CLIENT FIN] ({:<8}) ({:<30}) rsp={} code={} err={}'.format(
                'shoot', task_name, server_rsp, status_code, err_msg)
            if status_code == AGENT_OK:
                self.logger.info(m)
                JLOG(GRMCODE_CLIENTJOB_SUCCESS, *(task_name,))
            else:
                self.logger.error(m)

            if server_rsp != None:
                if len(server_rsp) > 0:
                    return json.loads(server_rsp[0][J_OB])
                else:
                    return self.make_outtask(task, status_code, '')
            else:
                return self.make_outtask(task, status_code, err_msg)

        except SOCKET_TIMEOUT:
            AgentLog.get_logger().error('%s' % agent_format_exc())
            return self.make_outtask(task, AGENT_NOK, 'TIMEOUT')
        except:
            AgentLog.get_logger().error('%s' % agent_format_exc())
            return self.make_outtask(task, AGENT_NOK, 'CLIENTJOB INTERNAL ERROR')

    def do_serverjob(self, agent_data):
        """
        do serverjob
        """

        job_no = agent_data[J_AGENT_DATA_JOBNO]
        client_id = agent_data[J_AGENT_DATA_CLIENTID]
        job = json.loads(agent_data[J_AGENT_DATA_JOBDATA])

        task_rsp_list = []
        job_status = AGENT_OK

        m = '$(JOBNO {})\nreceived from server'.format(job_no)
        send_journallog(m, JOURNAL_INFO, GRMCODE_JOB_RECEIVED)

        for task in job:
            job_process_msg = taskname = task[J_MOD][J_TASK][J_TASKN]
            taskdesc = tasktype = None
            if J_TASK_DESC in task[J_MOD][J_TASK]:
                taskdesc = task[J_MOD][J_TASK][J_TASK_DESC]
                if taskdesc:
                    job_process_msg = taskdesc
            if J_TASK_TYPE in task[J_MOD][J_TASK]:
                tasktype = task[J_MOD][J_TASK][J_TASK_TYPE]

            task_rsp_list.append(self.do_task(task))
            if task[J_MOD][J_TASK][J_OUT][J_STATUS] == AGENT_OK:
                if task[J_MOD][J_TASK][J_OUT][J_MESSAGE] == SKEEP_SERVER_REQUEST:
                    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = AGENT_DEFAULT_MESSAGE

                m = '$({}:{})processing ok'.format(job_no,taskname)
                send_journallog(m, JOURNAL_INFO, GRMCODE_JOB_PROC_OK)

                '''
                if not tasktype or not 'invisiable' in tasktype:
                    ma = '{}:{}\n수행했습니다'.format(job_no,job_process_msg)
                    self.data_center.GOOROOM_AGENT.agent_msg(ma)
                '''
            else:
                job_status = AGENT_NOK

                m = '$({}:{})processing nok:$({})'.format(
                    job_no, taskname, task[J_MOD][J_TASK][J_OUT][J_MESSAGE])
                send_journallog(m, JOURNAL_INFO, GRMCODE_JOB_PROC_NOK)

                '''
                if not tasktype or not 'invisiable' in tasktype:
                    ma = '{}:{}\n수행하지 못했습니다'.format(job_no,job_process_msg)
                    self.data_center.GOOROOM_AGENT.agent_msg(ma)
                '''
                break
                
        server_rsp, status_code, err_msg = \
            self.data_center.serverjob_request(task_rsp_list, job_no, job_status)
        m = '[SERVER FIN] ({:<8}) ({:<10}) rsp={} code={} err={}'.format(
            'shoot', job_no, server_rsp, status_code, err_msg)
        if status_code == AGENT_OK:
            self.logger.info(m)
            m = '$({})transmit ok'.format(job_no)
            send_journallog(m, JOURNAL_INFO, GRMCODE_JOB_TRANS_OK)
        else:
            self.logger.error(m)
            m = '$({})transmit nok:$({})'.format(job_no, err_msg)
            send_journallog(m, JOURNAL_INFO, GRMCODE_JOB_TRANS_NOK)

    def run(self):
        """
        run
        """

        #설정파일에 기재된 생존시간동안 JOB이 없으면 Worker는 은퇴
        self.last_job_time = time.time()

        Q = None
        DO_JOB = None

        if self.role == SERVERJOB:
            Q = self.data_center.serverjob_Q
            DO_JOB = self.do_serverjob
        else:
            Q = self.data_center.clientjob_Q
            DO_JOB = self.do_clientjob

        while True:
            job = None

            try:
                job = Q.get(True, 1)

                DO_JOB(job)

                self.last_job_time = time.time()

            except queue.Empty:
                if time.time() - self.last_job_time > self.data_center.worker_lifetime:
                    self.logger.error('A WORKER(%s) RETIRING' % self.role)
                    break
            except:
                self.logger.error('%s' % agent_format_exc())

        self.logger.info('A WORKER(%s) RETIRED' % self.role)

    def retiring(self):
        """
        Worker가 은퇴하는 순간 JOB이 주어지는 것을 방지하기 위해서
        생존시간의 90% 동안 일이 없으면 이 Worker에게는 Job이 주어지지 않고
        남은 10% 시간 후에 은퇴하도록 함.
        """

        if not self.last_job_time:
            return False

        idle_rate = float(time.time() - self.last_job_time) / float(self.data_center.worker_lifetime)

        return idle_rate > 0.9

    def alive(self):
        return self.is_alive()

