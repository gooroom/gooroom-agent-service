#!/usr/bin/env python3

#-----------------------------------------------------------------------
import xml.etree.ElementTree as etree
import simplejson as json
import datetime
import glob

from agent_define import *

#-----------------------------------------------------------------------
class SimpleParser:
    """
    simple parser
    """

    def __init__(self, mod_tmpl_path, ns):

        #[modulename][taskname] = [M, T, I, O]
        self._mod_tmpls = {}

        self.mod_tmpl_path = mod_tmpl_path
        if self.mod_tmpl_path[-1] != '/':
            self.mod_tmpl_path += '/'

        self.ns = ns

        self.load_tmpls()

    def load_tmpls(self):
        """
        load mododule templates
        """
        
        tmpl_fullpath = '%s*.%s' % (self.mod_tmpl_path, T_EXT)

        #each module
        for tmpl in glob.glob(tmpl_fullpath):
            tree = etree.parse(tmpl)
            t_mod = tree.getroot()

            mod_name = t_mod.attrib[T_NAME]
            self._mod_tmpls[mod_name] = {}

            t_tasks = t_mod.findall(self.ns+T_TASK)

            #each task
            for t_task in t_tasks:
                t_in = t_task.find(self.ns+T_IN)
                t_out = t_task.find(self.ns+T_OUT)

                task_name = t_task.attrib[T_NAME]
                mod_task = self._mod_tmpls[mod_name][task_name] = [t_mod, t_task, t_in, t_out]

    def dbusable_tasks(self):
        """
        return tasks which is allowed for dbus
        """

        #[ (modulename:taskname), ]
        tasks = []

        for mod_name in self._mod_tmpls:
            for task_name in self._mod_tmpls[mod_name]:
                salt = self._mod_tmpls[mod_name][task_name][1].attrib

                if T_DBUS in salt and salt[T_DBUS].lower() == 'allow':
                    tasks.append( (mod_name, task_name) )

        return tasks

    def clientjob_book(self):
        """
        client job processing 에서 사용할 {polltime:task_list}
        """

        infos = {}

        for mod_name in self._mod_tmpls:
            for task_name in self._mod_tmpls[mod_name]:
                salt = self._mod_tmpls[mod_name][task_name][1].attrib
                if not T_POLLTIME in salt:
                    continue

                polltime = int(salt[T_POLLTIME])

                version = SERVER_VERSION_1_0
                if T_VERSIONINFO in salt:
                    version = salt[T_VERSIONINFO]

                infos.setdefault(polltime, []).append(
                    ({J_MOD:{J_MODN:mod_name, J_TASK:{J_TASKN:task_name, J_IN:{}}}}, version))

        return infos

    def bootable_tasks(self):
        """
        return bootable task list
        """

        tasks = []
        for_priority_sort = []

        for mod_name in self._mod_tmpls:
            for task_name in self._mod_tmpls[mod_name]:
                salt = self._mod_tmpls[mod_name][task_name][1].attrib
                if T_BOOTABLE in salt:
                    if 'yes' == salt[T_BOOTABLE].lower():
                        mustok = 'ok'
                        if T_MUSTOK in salt:
                            mustok = salt[T_MUSTOK].lower() 

                        priority = 0
                        if T_PRIORITY in salt:
                            priority = int(salt[T_PRIORITY])
                        
                        version = SERVER_VERSION_1_0
                        if T_VERSIONINFO in salt:
                            version = salt[T_VERSIONINFO]

                        module = {J_MOD:{J_MODN:mod_name, J_TASK:{J_TASKN:task_name, J_IN:{}}}}
                        for_priority_sort.append((priority,module,mustok,version))

        from operator import itemgetter
        return [(m,mok,v) for p, m, mok, v in sorted(for_priority_sort, key=itemgetter(0))]

