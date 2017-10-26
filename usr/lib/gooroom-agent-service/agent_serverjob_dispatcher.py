#! /usr/bin/env python3

#-----------------------------------------------------------------------
import threading
import time
import multiprocessing
import simplejson as json
from socket import timeout as SOCKET_TIMEOUT

from agent_util import AgentConfig,AgentLog,agent_format_exc
from agent_msslrest import AgentMsslRest
from agent_job_worker import AgentJobManager
from agent_simple_parser import SimpleParser
from agent_data_center import AgentDataCenter
from agent_define import SERVERJOB

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

        #THREAD ESCAPE FLAG
        self._turn_on = True

        #thread의 conditional signal을 multiprocessing의 Event를 사용
        #시스템 시간을 변경했을 때 문제가 있어서 교체필요함
        self._dispatch_event = threading.Event()
        self._dispatch_event.clear()

        #서버와의 통신장애 횟수
        self.timeout_cnt = 0

        #Worker를 관리할 Manager생성
        self._job_manager = AgentJobManager(SERVERJOB, self.data_center)

    def run(self):
        """
        main loop   
        """

        self.logger.debug('(serverjob) dispatcher run')

        #timeout이 발생하면 waiting_time은 증가하고
        #정상화되면 dispatch_time으로 복구된다.
        #timeout_on을 확인.
        waiting_time = self.data_center.serverjob_dispatch_time

        #timeout 발생횟수
        timeout_cnt = 0

        while self._turn_on:
            if self.data_center.serverjob_looping_on[0]:

                try:
                    agent_data, _, _ = self.data_center.jobs_request()
                    if timeout_cnt:
                        waiting_time, timeout_cnt = self.timeout_off()
                    else:
                        waiting_time = self.data_center.serverjob_dispatch_time

                    if agent_data:
                        for job in agent_data:
                            self._job_manager.put_job(job)

                except SOCKET_TIMEOUT:
                    waiting_time, timeout_cnt = self.timeout_on(waiting_time, timeout_cnt)
                    AgentLog.get_logger().error('%s' % agent_format_exc())

                except: 
                    AgentLog.get_logger().error('%s' % agent_format_exc())

            self._dispatch_event.wait(timeout=waiting_time)

        self.logger.debug('(server) dispatcher turnoff')

    def timeout_on(self, waiting_time, timeout_cnt):
        """
        timeout on
        """

        if timeout_cnt < 3:
            return waiting_time, timeout_cnt+1

        #timeout이 연속 3번 이상 발생하면 client_dispatcher를 중단시키고
        if self.data_center.clientjob_looping_on[0]:
            self.data_center.clientjob_looping_on[0] = False

        #waiting_time을 2배씩 증가시키고
        waiting_time *= 2

        # waiting time이 최대값을 넘으면 최대값으로 고정시킨다.
        max_waiting_time = self.data_center.serverjob_max_dispatch_time
        if waiting_time > max_waiting_time:
            return max_waiting_time, timeout_cnt
        else:
            return waiting_time, timeout_cnt

    def timeout_off(self):
        """
        timeout off
        """

        if not self.data_center.clientjob_looping_on[0]:
            self.data_center.clientjob_looping_on[0] = True

        return self.data_center.serverjob_dispatch_time, 0

    def down(self):
        """
        thread down
        """

        self._turn_on = False
        self._dispatch_event.set()
        self.join()

        self._job_manager.allkill()

        self.logger.debug('(server) dispatcher down')

