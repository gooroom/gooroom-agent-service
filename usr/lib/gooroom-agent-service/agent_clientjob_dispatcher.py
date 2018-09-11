#! /usr/bin/env python3

#-----------------------------------------------------------------------
import simplejson as json
import threading
import time
import copy

from agent_util import AgentConfig,AgentLog,agent_format_exc
from agent_job_worker import AgentJobManager,AgentJobWorker
from agent_simple_parser import SimpleParser
from agent_define import *

#-----------------------------------------------------------------------
class AgentClientJobDispatcher(threading.Thread):
    """
    단말의 client Jobs을 처리해서 그 결과를 서버에게 전송
    """

    def __init__(self, data_center):

        threading.Thread.__init__(self)

        self.conf = AgentConfig.get_config()
        self.logger = AgentLog.get_logger()

        #DATA CENTER
        self.data_center = data_center

        #THREAD EVENT
        #시스템 시간을 변경했을 때 문제가 있어서 교체
        self._collect_event = threading.Event()
        self._collect_event.clear()

        #WORKER MANAGER
        self._job_manager = AgentJobManager(CLIENTJOB, self.data_center)

        #SPECIAL WORKER FOR DBUS
        self._special_worker = AgentJobWorker(CLIENTJOB, self.data_center)

    def dbus_do_task(self, task):
        """
        dbus를 통해 전달된 clientjob을 module에게 전달
        """

        return self._special_worker.do_clientjob(task)

    def run(self):
        """
        main loop   
        """

        self.logger.debug('(client) dispatcher run')

        intervals = 0

        while self.data_center.clientjob_dispatcher_thread_on:
            if self.data_center.clientjob_looping_on[0]:
                try:
                    intervals += 1

                    #self.data_center.center_lock.acquire()

                    for polltime in self.data_center.clientjob_book.keys():
                        if intervals % polltime is 0:
                            #clientjob은 task 단위로 처리
                            for task, version in self.data_center.clientjob_book[polltime]:
                                if self.data_center.server_version == SERVER_VERSION_1_0 \
                                    and version != SERVER_VERSION_1_0:
                                    continue

                                self._job_manager.put_job(copy.deepcopy(task))

                    if intervals % 60 is 0:
                        self.data_center.clear_max_response_time()
                        self.data_center.clear_timeout_cnt()
                except:
                    self.logger.error('%s' % agent_format_exc())

                finally:
                    #self.data_center.center_lock.release()
                    pass

            self._collect_event.wait(timeout=1.0)

        self.logger.debug('(client) dispatcher turnoff')

    def down(self):
        """
        thread down
        """

        self.data_center.clientjob_dispatcher_thread_on = False
        self._collect_event.set()
        self.join()

        self._job_manager.allkill()

        self.logger.debug('(client) dispatcher down')

