#!/usr/bin/env python3

#-----------------------------------------------------------------------
import math

from ctypes import *
#-----------------------------------------------------------------------

WSCP_LIB_PATH = '/usr/lib/x86_64-linux-gnu/libscpdb_agent.so'
WSCP_INI_PATH = '/usr/share/gooroom/BA-SCP/Config/scpdb_agent.ini'

class WrappedSCP:
    """
    Wrapped SCP
    """

    def __init__(self, bufSize=1024):

        self.bufSize = bufSize
        self.clib = CDLL(WSCP_LIB_PATH)

    def scp_encrypt(self, plain_txt):
        """
        scp_encrypt
        """

        encrypted_list = []
        encrypted_msg = create_string_buffer(self.bufSize*2)
        encrypted_len = c_int()

        for i in range(math.ceil(len(plain_txt)/self.bufSize)):
            plain_msg = create_string_buffer(
                    bytes(plain_txt[i*self.bufSize : (i+1)*self.bufSize], "utf8"))
            ret = self.clib.SCP_EncB64(WSCP_INI_PATH.encode(),
                    b'KEY1', plain_msg, len(plain_msg.value),
                    encrypted_msg, byref(encrypted_len), sizeof(encrypted_msg))
            if ret:
                return ret, []
            encrypted_list.append(encrypted_msg.value.decode('utf-8'))

        return ret, encrypted_list

    def scp_decrypt(self, encrypted_list):
        """
        scp_decrypt
        """

        decrypted_str = ''
        decrypted_msg = create_string_buffer(self.bufSize*2)
        decrypted_len = c_int()

        for encrypted_txt in encrypted_list:
            encrypted_msg = create_string_buffer(bytes(encrypted_txt, "utf8"))
            ret = self.clib.SCP_DecB64(WSCP_INI_PATH.encode(),
                    b'KEY1', encrypted_msg, len(encrypted_msg.value),
                    decrypted_msg, byref(decrypted_len), sizeof(decrypted_msg))
            if ret:
                return ret, ''
            decrypted_str += decrypted_msg.value.decode('utf-8')

        return ret, decrypted_str
