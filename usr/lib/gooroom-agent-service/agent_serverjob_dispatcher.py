#! /usr/bin/env python3

#-----------------------------------------------------------------------
from socket import timeout as SOCKET_TIMEOUT
import simplejson as json
import threading
import copy
import time

from agent_util import AgentConfig,AgentLog,agent_format_exc,JLOG
from agent_msslrest import AgentMsslRest
from agent_job_worker import AgentJobManager,AgentJobWorker
from agent_data_center import AgentDataCenter
from agent_simple_parser import SimpleParser
from agent_define import *
from agent_error import *

#-----------------------------------------------------------------------
class AgentServerJobDispatcher(threading.Thread):
    """
    Agent Server로 부터 JOB을 가져와서 Module(Plugin)을 처리할 
    Worker(Process)에게 JOB을 전달
    """

    def __init__(self, data_center): 

        threading.Thread.__init__(self)

        self.conf = AgentConfig.get_config()
        self.logger = AgentLog.get_logger()

        #DATA CENTER
        self.data_center = data_center

        #시스템 시간을 변경했을 때 문제가 있어서 교체필요함
        self._dispatch_event = threading.Event()
        self._dispatch_event.clear()

        #서버와의 통신장애 횟수
        self.timeout_cnt = 0

        #Worker를 관리할 Manager생성
        self._job_manager = AgentJobManager(SERVERJOB, self.data_center)

        #SPECIAL WORKER FOR SYNC
        self._special_worker = AgentJobWorker(CLIENTJOB, self.data_center)

    def run(self):
        """
        main loop   
        """

        self.logger.debug('(serverjob) dispatcher run')
        
        #################
        self.agent_sync()
        #################

        #동기화 과정이 오래 걸려서 메인루핑 내에서 동기화 과정이
        #반복적으로 실행되는 것을 막는 플래그
        sync_done = True

        while self.data_center.serverjob_dispatcher_thread_on:
            if self.data_center.serverjob_looping_on[0]:
                try:
                    #get jobs
                    agent_data, agent_status, err_msg = self.data_center.jobs_request()

                    prev_access_difftime = INIT_PREV_ACCESS_DIFFTIME
                    try:
                        prev_access_difftime = int(self.data_center.prev_access_difftime)
                    except:
                        AgentLog.get_logger().error(agent_format_exc())
                        
                    self.data_center.prev_access_difftime = \
                        INIT_PREV_ACCESS_DIFFTIME
                        
                    if prev_access_difftime > INIT_PREV_ACCESS_DIFFTIME:
                        if not sync_done and self.data_center.serverjob_dispatch_time \
                            - prev_access_difftime \
                            + 10 < 0:

                            #################
                            self.agent_sync()
                            #################
                            sync_done = True
                        else:
                            sync_done = False
                    else:
                        AgentLog.get_logger().error(
                            '!! prev_access_difftime is wrong value({})'.format(prev_access_difftime))

                    if agent_data:
                        for job in agent_data:
                            self._job_manager.put_job(job)

                    if agent_status == AGENT_OK:
                        if not self.data_center.agent_grm_connection_status[0]:
                            JLOG(GRMCODE_AGENT_CONNECTED, *('',))
                        self.data_center.agent_grm_connection_status[0] = True
                    else:
                        if self.data_center.agent_grm_connection_status[0]:
                            JLOG(GRMCODE_AGENT_DISCONNECTED, *(err_msg,))
                        self.data_center.agent_grm_connection_status[0] = False
                except: 
                    if self.data_center.agent_grm_connection_status[0]:
                        JLOG(GRMCODE_AGENT_DISCONNECTED, *(agent_format_exc(),))
                    self.data_center.agent_grm_connection_status[0] = False
                    AgentLog.get_logger().error(agent_format_exc())

            #start clientjob
            self.data_center.clientjob_looping_on[0] = True
            self._dispatch_event.wait(timeout=self.data_center.serverjob_dispatch_time)

        self.logger.debug('(server) dispatcher turnoff')

    def down(self):
        """
        thread down
        """

        self.data_center.serverjob_dispatcher_thread_on = False
        self._dispatch_event.set()
        self.join()

        self._job_manager.allkill()

        self.logger.debug('(server) dispatcher down')

    def timing(self, tm):
        """
        when sync-step is failed it defines waiting time for retrying
        """

        i = 0
        while self.data_center.serverjob_dispatcher_thread_on:
            yield i % tm == 0
            i += 1
            time.sleep(1)

    def agent_sync(self):
        """
        agent sync
        """
        
        try:
            INIT_RETRY_TIME = int(self.conf.get('MAIN', 'INIT_RETRY_TIME'))

            ting = self.timing(INIT_RETRY_TIME)

            for task_info in self.data_center.bootable_tasks:
                task, mustok = task_info
                ting = self.timing(INIT_RETRY_TIME)

                while True:
                    if next(ting):
                        result = self._special_worker.do_clientjob(copy.deepcopy(task))

                        if result[J_MOD][J_TASK][J_OUT][J_STATUS] != AGENT_OK:
                            task_name = result[J_MOD][J_TASK][J_TASKN]

                            if mustok == 'no':
                                break

                            self.logger.error('RETRY after %dsecs in INIT-TASK(%s)' 
                                % (INIT_RETRY_TIME, task_name))
                        else:
                            break

        except StopIteration:
            pass
        except:
            self.logger.error('%s' % agent_format_exc())

