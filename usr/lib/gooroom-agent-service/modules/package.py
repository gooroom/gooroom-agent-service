#! /usr/bin/env python3

#-----------------------------------------------------------------------
import apt
import os

from agent_util import AgentConfig,AgentLog,agent_format_exc
from agent_define import *

#-----------------------------------------------------------------------
MAX_PACKAGE_NUM = 1000

#-----------------------------------------------------------------------
def do_task(task, data_center):
    """
    do task
    """

    task[J_MOD][J_TASK][J_OUT] = \
        {J_STATUS : AGENT_OK, J_MESSAGE : AGENT_DEFAULT_MESSAGE}

    cache = None

    try:
        cache = get_cache()
        eval('task_%s(task, data_center, cache)' % task[J_MOD][J_TASK][J_TASKN])

    except:
        task[J_MOD][J_TASK][J_OUT][J_STATUS] = AGENT_NOK
        e = agent_format_exc()
        task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = e

        AgentLog.get_logger().error(e)

    if cache:
        cache.close()

    if J_IN in task[J_MOD][J_TASK]:
        task[J_MOD][J_TASK].pop(J_IN)
    if J_REQUEST in task[J_MOD][J_TASK]:
        task[J_MOD][J_TASK].pop(J_REQUEST)
    if J_RESPONSE in task[J_MOD][J_TASK]:
        task[J_MOD][J_TASK].pop(J_RESPONSE)

    return task

#-----------------------------------------------------------------------
def task_install_or_upgrade_package(task, data_center, cache):
    """
    install_package
    """

    check_package_operation(data_center)

    pkg_list = task[J_MOD][J_TASK][J_IN]['pkgs'].split(',')

    for pkg_name in pkg_list:
        pkg = cache[pkg_name]

        if pkg.is_installed:
            if pkg.is_upgradable:
                pkg.mark_upgrade()
        else:
            pkg.mark_install()

        pkg.mark_install()

    agent_commit(task, cache)

#-----------------------------------------------------------------------
def task_remove_package(task, data_center, cache):
    """
    remove_package
    """

    check_package_operation(data_center)

    pkg_list = task[J_MOD][J_TASK][J_IN]['pkgs'].split(',')

    for pkg_name in pkg_list:
        pkg = cache[pkg_name]
        pkg.mark_delete()

    mark_status = get_mark_status(cache)
    aap = AgentAcquireProgress()
    aip = AgentInstallProgress()
    m = ''

    agent_commit(task, cache)

#-----------------------------------------------------------------------
def task_upgrade_all(task, data_center, cache):
    """
    upgrade_all
    """

    check_package_operation(data_center)

    cache.upgrade()
    agent_commit(task, cache)

#-----------------------------------------------------------------------
def task_upgrade_package_with_label(task, data_center, cache):
    """
    upgrade_label
    """

    check_package_operation(data_center)

    label_list = task[J_MOD][J_TASK][J_IN]['label_list'].split(',')

    for label in label_list:
        cnt = 0
        for pkg in cache:
            if pkg.is_installed \
                and pkg.is_upgradable \
                and pkg.candidate \
                and pkg.candidate.orgins:

                label_idx = len(pkg.candidate.origins)

                if label_idx == 1:
                    label_idx = 0
                else:
                    label_idx = 1

                if label in pkg.candidate.origins[label_idx].label:
                    cnt += 1
                    pkg.mark_upgrade()

    agent_commit(task, cache)

#-----------------------------------------------------------------------
def task_insert_all_packages_to_server(task, data_center, cache):
    """
    insert_all_packages_to_server
    """

    task[J_MOD][J_TASK][T_REQUEST] = {}
    task[J_MOD][J_TASK][J_REQUEST][J_ID] = 'head'

    cnt = 0
    tmp_list = []
    first_time = True

    pkg_list = read_all_pkgs_list_in_cache(cache)

    for pkg in pkg_list:
        if cnt >= MAX_PACKAGE_NUM:
            task[J_MOD][J_TASK][J_REQUEST]['pkg_list'] = tmp_list
            data_center.module_request(task, mustbedata=False)

            task[J_MOD][J_TASK][T_REQUEST] = {}
            task[J_MOD][J_TASK][J_REQUEST][J_ID] = 'next'
            cnt = 0
            tmp_list = []
            
        tmp_list.append(pkg)
        cnt += 1

    if len(tmp_list):
        task[J_MOD][J_TASK][J_REQUEST]['pkg_list'] = tmp_list
        data_center.module_request(task, mustbedata=False)

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def _send_pkg(data_center, task):
    """
    devide and transmit
    """

    pkg_list = task[J_MOD][J_TASK][J_REQUEST]['pkg_list']
    send_cnt = len(task[J_MOD][J_TASK][J_REQUEST]['pkg_list']) // MAX_PACKAGE_NUM + 1

    for i in range(send_cnt):
        if i+1 != send_cnt:
            task[J_MOD][J_TASK][J_REQUEST]['pkg_list'] = \
                pkg_list[i*MAX_PACKAGE_NUM:(i+1)*MAX_PACKAGE_NUM]
        else:
            task[J_MOD][J_TASK][J_REQUEST]['pkg_list'] = pkg_list[i*MAX_PACKAGE_NUM:]

        data_center.module_request(task, mustbedata=False, remove_request=False)

def task_update_package_version_to_server(task, data_center, cache):
    """
    update_package_version_to_server
    """

    fullpath = create_pkglist_file()

    #cache에서 설치된 패키지 리스트를 가져오고
    cache_packages = read_installed_pkgs_in_cache(cache)

    #파일이 없으면
    if not os.path.exists(fullpath):
        #서버에게 리스트 전체를 전송한 후
        package_list = ['{},{}'.format(k,','.join(v)) for k, v in cache_packages.items()]

        task[J_MOD][J_TASK][T_REQUEST] = {}
        task[J_MOD][J_TASK][J_REQUEST][J_ID] = 'installed'
        task[J_MOD][J_TASK][J_REQUEST]['pkg_list'] = package_list

        #data_center.module_request(task, mustbedata=False)
        _send_pkg(data_center, task)

        #서버의 응답이 정상(module_request에서 예외가 발생하지 않으면)
        #파일에 저장
        with open(fullpath, 'w') as f:
            f.writelines('\n'.join(package_list))

    #파일이 있으면
    else:
        #파일에서 설치된 패키지 리스트를 가져오고
        file_packages = read_installed_pkgs_in_file(fullpath)

        unmatched_pkg_list = []

        #파일과 캐쉬를 비교해서
        for c_pkgname in cache_packages:
            c_iv = cache_packages[c_pkgname][0]
            c_cv = cache_packages[c_pkgname][1]
            c_arch = cache_packages[c_pkgname][2]
            c_label = cache_packages[c_pkgname][3]

            if c_pkgname in file_packages:
                f_iv = file_packages[c_pkgname][0]
                f_cv = file_packages[c_pkgname][1]

                #설치버전과 후보버전이 모두 일치하면 무싱
                if c_iv == f_iv and c_cv == f_cv:
                    file_packages.pop(c_pkgname)
                    continue

                file_packages.pop(c_pkgname)

            #cache에 있는 패키지가 파일에 없으면 새로 설치된 패키지
            else:
                pass

            unmatched_pkg_list.append('%s,%s,%s,%s,%s,%s' 
                % (c_pkgname, c_iv, c_cv, c_arch, c_label, 'U'))

        #캐쉬에 있는 패키지는 file_packages.pop()을 통해
        #삭제되었기 때문에 남아있는 패키지들은 캐쉬에 없는
        #즉 삭제된 패키지들
        for f_pkgname in file_packages:
            f_iv = file_packages[f_pkgname][0]
            f_cv = file_packages[f_pkgname][1]
            f_arch = file_packages[f_pkgname][2]
            f_label = file_packages[f_pkgname][3]

            unmatched_pkg_list.append('%s,%s,%s,%s,%s,%s' 
                % (f_pkgname, f_iv, f_cv, f_arch, f_label, 'D'))
            
        #업데이트할 패키지가 있으면(없으면 끝)
        if len(unmatched_pkg_list) > 0:
            task[J_MOD][J_TASK][J_REQUEST] = {}
            task[J_MOD][J_TASK][J_REQUEST][J_ID] = 'updating'
            task[J_MOD][J_TASK][J_REQUEST]['pkg_list'] = unmatched_pkg_list

            #data_center.module_request(task, mustbedata=False)
            _send_pkg(data_center, task)

            #서버의 응답이 정상(module_request가 예외를 발생시키지 않으면)
            #파일 업데이트
            package_list = ['{},{}'.format(k,','.join(v)) for k, v in cache_packages.items()]
            with open(fullpath, 'w') as f:
                f.write('\n'.join(package_list))

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = SKEEP_SERVER_REQUEST
    return task

#-----------------------------------------------------------------------
def get_cache():
    """
    get cache 
    """

    cache = apt.cache.Cache()
    cache.update()
    cache.open()

    return cache

#-----------------------------------------------------------------------
def read_all_pkgs_list_in_cache(cache):
    """
    return all packages in cache
    """

    cache_packages = []

    for pkg in cache:
        if not pkg.candidate:
            continue

        label = None
        if pkg.candidate.origins and pkg.candidate.origins:
            label_idx = len(pkg.candidate.origins)
            if label_idx == 1:
                label_idx = 0
            else:
                label_idx = 1
            label = pkg.candidate.origins[label_idx].label

            if not label:
                label = 'null'

        cache_packages.append('%s,%s,%s,%s' 
            % (pkg.name, pkg.architecture(), label, pkg.candidate.version))

    return cache_packages

#-----------------------------------------------------------------------
def read_installed_pkgs_in_cache(cache):
    """
    return installed packages in cache
    """

    cache_packages = {}

    for pkg in cache:
        if pkg.is_installed:
            candi_ver = pkg.installed.version
            if pkg.candidate:
                candi_ver = pkg.candidate.version

            label = None
            if pkg.installed.origins and pkg.installed.origins:
                label_idx = len(pkg.installed.origins)
                if label_idx == 1:
                    label_idx = 0
                else:
                    label_idx = 1
                label = pkg.installed.origins[label_idx].label

                if not label:
                    label = 'null'

            cache_packages[pkg.name] = \
                [pkg.installed.version, candi_ver, pkg.architecture(), label]

    return cache_packages

#-----------------------------------------------------------------------
def read_installed_pkgs_in_file(fullpath):
    """
    return installed packages in file
    """

    file_packages = {}

    with open(fullpath) as f:
        for l in f.readlines():
            n,*i = l.split(',')
            file_packages[n] = i
    
    return file_packages

#-----------------------------------------------------------------------
def create_pkglist_file():
    """
    create file of package list 
    """

    fullpath = AgentConfig.get_config().get('MAIN', 'AGENT_BACKUP_PATH')
    if fullpath[-1] != '/':
        fullpath += '/'

    if not os.path.isdir(fullpath):
        os.makedirs(fullpath)

    key_path = AgentConfig.get_config().get('MAIN', 'AGENT_KEY')
    fullpath += 'package-version-enum-%f' % os.stat(key_path).st_ctime
    return fullpath

#-----------------------------------------------------------------------
def agent_commit(task, cache):
    """
    commit
    """

    mark_status = get_mark_status(cache)
    aap = AgentAcquireProgress()
    aip = AgentInstallProgress()
    m = ''

    if cache.commit(fetch_progress=aap, install_progress=aip):
        m += 'install[%d] upgrade[%d] delete[%d]\n' \
            % (len(mark_status['I']), 
                len(mark_status['U']), 
                len(mark_status['D']))

        for action in ('I', 'U', 'D'):
            m += '[%s:%d] %s\n' % (action, 
                                len(mark_status[action]), 
                                '\n'.join(mark_status[action]))
    else:
        m += '%s\n%s' % (aap.get_message(), aip.get_message())
        #task[J_MOD][J_TASK][J_OUT][J_STATUS] = AGENT_NOK

    task[J_MOD][J_TASK][J_OUT][J_MESSAGE] = m

    cache.commit()

#-----------------------------------------------------------------------
def get_mark_status(cache):
    """
    return marking status of packages in cache
    """

    #[ [install], [upgrade], [delete] ]
    ms = {'I':[], 'U':[], 'D':[]}

    for pkg in cache:
        if pkg.marked_install:
            ms['I'].append(pkg.name)    
        elif pkg.marked_upgrade:
            ms['U'].append(pkg.name)    
        elif pkg.marked_delete:
            ms['D'].append(pkg.name)    

    return ms

#-----------------------------------------------------------------------
def check_package_operation(data_center):
    """
    check package_operation
    """

    if data_center.package_operation != 'enable':
        raise Exception('package-operation is turned off by security-status-plugin.')
        
#-----------------------------------------------------------------------
from apt.progress.base import InstallProgress, AcquireProgress

class AgentInstallProgress(InstallProgress):
    """
    apt package install progress 
    """
    
    message = []

    def error(self, pkg, errormsg):
        """
        invoked when apt's action is failed 
        """

        super().error(pkg, errormsg)
        self.message.append('%s: %s' % (pkg, errormsg))

    def get_message(self):
        """ get message """
        return '\n'.join(self.message)


class AgentAcquireProgress(AcquireProgress):
    """
    apt package acquire progress
    """

    message = []

    def fail(self, item):
        """
        invoked when it is failed to download packages
        """

        self.message.append(item.description)

    def get_message(self):
        """ get message """
        return '\n'.join(self.message)

