#! /usr/bin/env python3

#-----------------------------------------------------------------------
import xml.etree.ElementTree as etree
import os
import shutil
import traceback

from collections import OrderedDict

from agent_util import AgentConfig, AgentLog
from agent_define import *

#-----------------------------------------------------------------------
def do_task(task, data_center):
    """
    do task
    """

    task[J_MOD][J_TASK][J_OUT] = {J_STATUS : AGENT_OK, J_ERR_REASON : ''}

    try:
        eval('task_%s(task,data_center)' % task[J_MOD][J_TASK][J_TASKN])

    except:
        task[J_MOD][J_TASK][J_OUT][J_STATUS] = AGENT_NOK
        e = traceback.format_exc()
        task[J_MOD][J_TASK][J_OUT][J_ERR_REASON] = e

        AgentLog.get_logger().error(e)

    if J_IN in task[J_MOD][J_TASK]:
        task[J_MOD][J_TASK].pop(J_IN)
    if J_REQUEST in task[J_MOD][J_TASK]:
        task[J_MOD][J_TASK].pop(J_REQUEST)
    if J_RESPONSE in task[J_MOD][J_TASK]:
        task[J_MOD][J_TASK].pop(J_RESPONSE)

    return task

#-----------------------------------------------------------------------
def task_replace_config(task, data_center):
    """
    replace_config
    """

    file_name = task[J_MOD][J_TASK][J_IN]['file_name']
    file_contents = task[J_MOD][J_TASK][J_IN]['file_contents']
    signature = task[J_MOD][J_TASK][J_IN]['signature']
    
    #if verifying is failed, exception occur
    verify_signature(signature, file_contents)

    replace_file(file_name, file_contents, signature)

#-----------------------------------------------------------------------
def task_get_update_server_config(task, data_center):
    """
    get_update_server_config
    """

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {}
    task[J_MOD][J_TASK][J_REQUEST][J_ID] = 'first'

    server_rsp = data_center.module_request(task)

    filenames = server_rsp[J_MOD][J_TASK][J_RESPONSE]['file_name_list']
    filecontents = server_rsp[J_MOD][J_TASK][J_RESPONSE]['file_contents_list']
    signatures = server_rsp[J_MOD][J_TASK][J_RESPONSE]['signature_list']

    len_filenames = len(filenames)
    len_filecontents = len(filecontents)
    len_signatures = len(signatures)

    if len_filenames != len_filecontents \
        and len_filecontents != len_signatures:
        raise Exception('!! invalid data len(filename)=%d len(filecontents)=%d len(signautres)=%d' 
            % (len_filenames, len_filecontents, len_signatures))
    
    for n, c, s in zip(filenames, filecontents, signatures):
        #if verifying is failed, exception occur
        verify_signature(s, c)
        
        replace_file(n, c, s)

    task[J_MOD][J_TASK][J_OUT][J_ERR_REASON] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_append_contents_etc_hosts(task, data_center):
    """
    append_contents
    """

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {}
    task[J_MOD][J_TASK][J_REQUEST][J_ID] = 'first'

    server_rsp = data_center.module_request(task)

    signature = server_rsp[J_MOD][J_TASK][J_RESPONSE]['signature']
    server_contents = server_rsp[J_MOD][J_TASK][J_RESPONSE]['file_contents']

    #if verifying is failed, exception occur
    verify_signature(signature, server_contents)

    remake_etc_hosts(parse_etc_hosts(server_contents), signature)

    task[J_MOD][J_TASK][J_OUT][J_ERR_REASON] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_get_server_certificate(task, data_center):
    """
    get_server_certificate
    """

    task[J_MOD][J_TASK].pop(J_IN)
    task[J_MOD][J_TASK][J_REQUEST] = {}
    task[J_MOD][J_TASK][J_REQUEST][J_ID] = 'first'

    server_rsp = data_center.module_request(task)

    file_contents = server_rsp[J_MOD][J_TASK][J_RESPONSE]['file_contents']

    replace_file('/etc/gooroom/agent/server_certificate.crt', file_contents)

    task[J_MOD][J_TASK][J_OUT][J_ERR_REASON] = SKEEP_SERVER_REQUEST

#-----------------------------------------------------------------------
def task_get_config(task, data_center):
    """
    get_config
    """

    file_name = task[J_MOD][J_TASK][J_IN]['file_name']

    tmpl_path = get_tmpl_path()
    config_file_list = get_enumvalues_from_xml(tmpl_path, 'CONFIG_FILE')


    if not file_name in config_file_list:
        raise Exception('invalid file_name, check config.tmpl')

    with open(file_name) as f:
        file_contents = f.read()
        task[J_MOD][J_TASK][J_OUT]['file_contents'] = file_contents

#-----------------------------------------------------------------------
def get_tmpl_path():
    """
    get module_templates path
    """

    tmpl_path = AgentConfig.get_config().get('MAIN', 'MODULE_TMPL_PATH')
    if tmpl_path[-1] != '/':
        tmpl_path += '/'

    return tmpl_path+'config.tmpl'

#-----------------------------------------------------------------------
def get_enumvalues_from_xml(xmlpath, typename):
    """
    return enum values of <simpleType> of xml
    """

    ns = AgentConfig.get_config().get('MAIN', 'MODULE_TMPL_NAMESPACE')
    tree = etree.parse(xmlpath)
    t_mod = tree.getroot()

    simple_types = t_mod.findall(ns+T_SIMPLETYPE)

    values = []

    for simple_type in simple_types:
        if typename == simple_type.attrib[T_NAME]:
            restrictions = simple_type.findall(ns+T_RESTRICTION)
            for restriction in restrictions:
                enums = restriction.findall(ns+T_SIMPLETYPE_ENUM)
                for enum in enums:
                    values.append(enum.attrib[T_VALUE])

    return values

#-----------------------------------------------------------------------
def replace_file(file_name, file_contents, signature=None):
    """
    replace file
    """

    tmpl_path = get_tmpl_path()
    config_file_list = get_enumvalues_from_xml(tmpl_path, 'CONFIG_FILE')

    if not file_name in config_file_list:
        raise Exception('invalid file_name, check config.tmpl')

    splited_filename = file_name.split('/')[-1]
    backup_path = AgentConfig.get_config().get('MAIN', 'AGENT_BACKUP_PATH')
    if backup_path[-1] != '/':
        backup_path += '/'

    dir_path = '%s%s/' % (backup_path, splited_filename)

    if not os.path.isdir(dir_path):
        os.makedirs(dir_path)

    if os.path.exists(file_name):
        #최초 원본파일을 보존하기위해서 원본보존파일(+agent_origin)이
        #없으면 현재파일을 복사
        agent_origin = dir_path+splited_filename+'+agent_origin'

        if not os.path.exists(agent_origin):
            shutil.copyfile(file_name, agent_origin) 

        agent_prev = dir_path+splited_filename+'+agent_prev'

        #백업파일(+agent_prev)이 있으면 삭제
        if os.path.exists(agent_prev):
            os.remove(agent_prev)

        #현재파일을 백업파일(+agent_prev)으로 이동
        shutil.move(file_name, agent_prev)

        #설정파일생성
        with open(file_name, 'w') as f:
            f.write(file_contents)

    else:
        #설정파일이 존재하지 않으면 생성하고 끝.
        #+agent_origin이나 +agent_prev가 존재하는 상태에서 설정파일만 없을 경우는
        #무시해도 생성할 파일이 최신이고 +agent_origin이 원본
        #+agent_prev가 이전파일이라는 지금 로직과 일치함.

        #설정파일생성
        with open(file_name, 'w') as f:
            f.write(file_contents)

    #signature
    if signature:
        with open(dir_path+splited_filename+'+signature', 'w') as f:
            f.write(signature)

#-----------------------------------------------------------------------
def parse_etc_hosts(contents):
    """
    parsing /etc/hosts
    """

    etc_hosts = contents.strip().rstrip('\n').split('\n')

    parsed_hosts = OrderedDict()

    for line in etc_hosts:
        line = line.rstrip()
        if not line or line[0] == '#':
            continue

        ip, *dns = line.split()

        #dns리스트에서 #주석 이후 내용은 삭제
        comment_removed_dns = []
        for d in dns:
            if d[0] == '#':
                break
            comment_removed_dns.append(d)
            
        parsed_hosts[ip] = comment_removed_dns

    return parsed_hosts

#-----------------------------------------------------------------------
def remake_etc_hosts(server_contents, signature):
    """
    remake /etc/hosts with altered contents after comparing local contenst with server's
    """

    tmp_logger = AgentLog.get_logger()
    tmp_logger.debug('BEGIN REMAKING HOSTS')

    #/etc/hosts 기존 내용과 변경된 내용을 저장할 리스트
    #로직이 완료되면 replace_file을 통해 /etc/hosts를 
    #리스트 내용으로 새로 생성
    altered_hosts = []

    with open('/etc/hosts') as f:
        #/etc/hosts파일을 읽어서
        #라인별로 서버에서 내려온 리스트와 비교
        for line in f.readlines():
            l_line = line.strip().split()
            tmp_logger.debug('LOCAL LINE=%s' % l_line)
            
            #주석과 아이피:도메인리스트 쌍이 안되는 것들은
            #그대로 새 파일에 출력
            if len(l_line) < 2 or l_line[0] == '#':
                altered_hosts.append(line)
                tmp_logger.debug('skip=%s' % l_line)
                continue

            l_ip, *l_dns = l_line

            #dns리스트에서 #주석 이후 내용은 삭제
            comment_removed_dns = []
            for d in l_dns:
                if d[0] == '#':
                    break
                comment_removed_dns.append(d)

            #주석이 제거된 dns리스트로 교체
            tmp_logger.debug('removed comment %s -> %s' % (l_dns, comment_removed_dns))
            l_dns = comment_removed_dns

            #로컬 아이피가 서버 리스트에 존재하면
            if l_ip in server_contents:
                s_dns = server_contents[l_ip]
                tmp_logger.debug('l_ip(%s) in server' % l_ip)

                #서버 리스트의 해당 아이피에 해당하는
                #dns 리스트 중에 중복 되지 않는 것만 기존 것에 추가
                new_dns = set(s_dns) - set(l_dns)
                tmp_logger.debug('no duplicated dns=%s' % new_dns)

                if new_dns:
                    #중복되지 않는 dns리스트를 모아놓고 일괄 반영
                    l_dns.extend(new_dns)
                    altered_hosts.append('%s %s #generated by gooroom-agent-service (domain added)\n' 
                        % (l_ip, ' '.join(l_dns)))
                else:
                    #중복없이 모두 일치하면 변경없이 저장
                    altered_hosts.append(line)

                #로컬에 없는 항목들만 남겨 놓고
                #마지막에 일괄적용하기 위해서 반영된 항목은 삭제
                server_contents.pop(l_ip)

            #로컬 아이피가 서버 리스트에 존재하지 않으면
            #로컬 dns리스트를 서버 리스트와 비교
            else:
                to_remove_ip = None

                for s_ip in server_contents:
                    s_dns = server_contents[s_ip]

                    #dns리스트 전부와 일치하면 ip를 교체
                    if set(l_dns) == set(s_dns):
                        altered_hosts.append('%s %s #generated by gooroom-agent-service (ip changed)\n' 
                            % (s_ip, ' '.join(l_dns)))
                        to_remove_ip = s_ip
                        tmp_logger.debug('ip changed line=%s' % line)
                        #중복은 무시
                        break

                if to_remove_ip:
                    #로컬에 없는 항목들만 남겨 놓고
                    #마지막에 일괄적용하기 위해서 반영된 항목은 삭제
                    server_contents.pop(to_remove_ip)
                else:
                    #dns도 일치하는게 없으면 그대로 저장
                    altered_hosts.append(line)
                    
        #로컬에 없는 항목들 일괄적용
        for s_ip in server_contents:
            s_dns = server_contents[s_ip]
            altered_hosts.append('%s %s #generated by gooroom-agent-service (new)\n' % (s_ip, ' '.join(s_dns)))
            tmp_logger.debug('new added s_ip=%s s_dns=%s' % (s_ip, s_dns))
                    
    if len(altered_hosts) == 0:
        tmp_logger.error('!! ZERO BUG')
        
    tmp_logger.debug('END REMAKING HOSTS')
        
    #/etc/hosts에 반영
    replace_file('/etc/hosts', ''.join(altered_hosts), signature)

#-----------------------------------------------------------------------
def verify_signature(signature, data):
    '''
    verify file signature
    '''

    import OpenSSL
    import base64

    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, 
        open('/etc/gooroom/agent/server_certificate.crt').read())

    OpenSSL.crypto.verify(cert, 
        base64.b64decode(signature.encode('utf8')), 
        data.encode('utf8'), 'sha256')
