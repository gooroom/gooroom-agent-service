#! /usr/bin/env python3

#-----------------------------------------------------------------------
import simplejson as json
import os

from agent_util import AgentConfig

#-----------------------------------------------------------------------
def update_usb_whitelist_state(*args):
    """
    update usb whitelist state into the file 
    for client|server usb event whitelist
    """

    if len(args) < 1:
        raise Exception('invalid argument number:{}'.format(args))
        
    config = AgentConfig.get_config()
    usb_whitelist_path = \
        config.get('MAIN', 'USB_WHITELIST_PATH')
    dir_path = '/'.join(usb_whitelist_path.split('/')[:-1])

    if not os.path.isdir(dir_path):
        os.makedirs(dir_path)

    with open(usb_whitelist_path) as fr:
        lines = [l.strip().split(',') for l in fr.readlines() if l.strip()]

    for idx, l in enumerate(lines):
        if not l or len(l) < 1:
            continue

        if l[0] == args[0]:
            l_len = len(l)
            for i, arg in enumerate(args):
                if arg == 'None':
                    continue

                if i < l_len:
                    l[i] = arg
                else:
                    l.append(arg)
            break
    else:
        lines.append(list(args)) 

    with open(usb_whitelist_path, 'w') as fw:
        if lines and len(lines) > 0:
            fw.write('\n'.join([','.join(l) for l in lines]))
        else:
            fw.write('')

#-----------------------------------------------------------------------
def delete_usb_whitelist_state(serial):
    """
    delete item of the file
    """

        
    config = AgentConfig.get_config()
    usb_whitelist_path = \
        config.get('MAIN', 'USB_WHITELIST_PATH')

    if not os.path.exists(usb_whitelist_path):
        return

    with open(usb_whitelist_path) as fr:
        lines = [l.strip().split(',') for l in fr.readlines() if l.strip()]

    for idx, l in enumerate(lines):
        if not l or len(l) < 1:
            continue

        if l[0] == serial:
            del lines[idx]

    with open(usb_whitelist_path, 'w') as fw:
        if lines and len(lines) > 0:
            fw.write('\n'.join([','.join(l) for l in lines]))
        else:
            fw.write('')

#-----------------------------------------------------------------------
def write_usb_register_state(file_contents):
    """
    write usb register state
    """

    config = AgentConfig.get_config()
    usb_whitelist_path = \
        config.get('MAIN', 'USB_WHITELIST_PATH')
    dir_path = '/'.join(usb_whitelist_path.split('/')[:-1])

    if not os.path.isdir(dir_path):
        os.makedirs(dir_path)

    fcs = json.loads(file_contents)
    usb_memory = fcs['usb_memory']
    with open(usb_whitelist_path, 'w') as f:
        if 'usb_status_board' in usb_memory:
            f.write('\n'.join(usb_memory['usb_status_board']))
        else:
            f.write('')

#-----------------------------------------------------------------------
def usb_whitelist_signal_msg(action, usb_serial, usb_name):
    """
    dbus signal of server-event about usb whitelist
    """

    if action == 'registering':
        m = '등록요청'
    elif action == 'register-approval':
        m = '등록승인'
    elif action == 'register-deny':
        m = '등록거절'
    elif action == 'registering-cancel':
        m = '등록요청취소'
    elif action == 'unregistering':
        m = '삭제요청'
    elif action == 'unregister-approval':
        m = '삭제승인'
    elif action == 'unregister-deny':
        m = '삭제거절'
    elif action == 'register-approval-cancel':
        m = '등록승인취소'
    elif action == 'register-deny-item-remove':
        m = '거절항목제거'

    return 'USB 이름:{} 시리얼번호:{}\n{} 되었습니다.'.format(usb_name, usb_serial, m)

