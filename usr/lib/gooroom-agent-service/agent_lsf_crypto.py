#!/usr/bin/env python3

#-----------------------------------------------------------------------
import ctypes
import os

#-----------------------------------------------------------------------
LSF_CRYPTO_LIB_PATH = '/usr/lib/x86_64-linux-gnu/liblsf-crypto.so'
LSF_PUBLIC_KEY_PATH = '/etc/ssl/private/gooroom_server.key'
#LSF_PUBLIC_KEY_PATH = '/etc/ssl/private/gooroom_public.key'
LSF_PRIVATE_KEY_PATH = '/etc/ssl/private/gooroom_client.key'
#LSF_PRIVATE_KEY_PATH = '/home/user/gkm_server.key'

LSF_RSA_PUBLICKEY_TYPE = 0
LSF_RSA_PRIVATEKEY_TYPE = 1

LSF_CRYPTO_SUCCESS = 0
LSF_CRYPTO_FAIL = 1

LSF_CRYPTO_ERRMSG_LEN = 256

NO_ERR_MSG = 'NO ERROR MSG'

#-----------------------------------------------------------------------
class LSF_ERROR_T(ctypes.Structure):
    _fields_ = [('message', ctypes.c_char * LSF_CRYPTO_ERRMSG_LEN)]

#-----------------------------------------------------------------------
def get_crypto_api():
    """
    get liblsf-crypto.so instance
    """

    if not os.path.exists(LSF_CRYPTO_LIB_PATH):
        raise Exception('LSF_CRYPTO_LIB NOT FOUND')

    api = ctypes.CDLL(LSF_CRYPTO_LIB_PATH)
    if not api:
        raise Exception('FAIL TO LOAD LSF_CRYPTO_LIB')

    lsf_magic_crypto_usable(api)
    return api

#-----------------------------------------------------------------------
def lsf_encrypt_RSA(api, plain_text):
    """
    lsf_read_key_MC_RSA_PKCS1
    lsf_encrypt_MC_RSAOAEP_SHA256
    lsf_base64_encode
    """

    crypto_error = ctypes.POINTER(LSF_ERROR_T)()

    rsa_decoded_public_key = ctypes.POINTER(ctypes.c_ubyte)()
    rsa_decoded_public_key_len = ctypes.c_int()
    r = api.lsf_read_key_MC_RSA_PKCS1(
                    LSF_PUBLIC_KEY_PATH.encode('utf-8'), 
                    LSF_RSA_PUBLICKEY_TYPE, 
                    ctypes.byref(rsa_decoded_public_key), 
                    ctypes.byref(rsa_decoded_public_key_len), 
                    ctypes.byref(crypto_error)
                    )

    if r != LSF_CRYPTO_SUCCESS:
        api.lsf_crypto_free(rsa_decoded_public_key)
        errm = crypto_error.contents.message if crypto_error else NO_ERR_MSG
        api.lsf_crypto_free(crypto_error)
        raise Exception('lsf_read_key_MC_RSA_PKCS1:{}'.format(errm))

    rsa_encrypted_text = ctypes.POINTER(ctypes.c_ubyte)()
    rsa_encrypted_text_len = ctypes.c_int()
    r = api.lsf_encrypt_MC_RSAOAEP_SHA256(
                                rsa_decoded_public_key, 
                                rsa_decoded_public_key_len, 
                                plain_text.encode('utf-8'), 
                                ctypes.byref(rsa_encrypted_text),
                                ctypes.byref(rsa_encrypted_text_len),
                                ctypes.byref(crypto_error)
                                )
    if r != LSF_CRYPTO_SUCCESS:
        api.lsf_crypto_free(rsa_decoded_public_key)
        api.lsf_crypto_free(rsa_encrypted_text)
        errm = crypto_error.contents.message if crypto_error else NO_ERR_MSG
        api.lsf_crypto_free(crypto_error)
        raise Exception('lsf_encrypt_MC_RSAOAEP_SHA256:{}'.format(errm))

    b64_encoded = ctypes.POINTER(ctypes.c_ubyte)()
    b64_encoded_len = ctypes.c_int()
    r = api.lsf_base64_encode(
                            rsa_encrypted_text, 
                            rsa_encrypted_text_len, 
                            ctypes.byref(b64_encoded),
                            ctypes.byref(b64_encoded_len),
                            ctypes.byref(crypto_error)
                            )
    if r != LSF_CRYPTO_SUCCESS:
        api.lsf_crypto_free(rsa_decoded_public_key)
        api.lsf_crypto_free(rsa_encrypted_text)
        api.lsf_crypto_free(b64_encoded)
        errm = crypto_error.contents.message if crypto_error else NO_ERR_MSG
        api.lsf_crypto_free(crypto_error)
        raise Exception('lsf_base64_encode:{}'.format(errm))

    api.lsf_crypto_free(rsa_decoded_public_key)
    api.lsf_crypto_free(rsa_encrypted_text)

    result = ctypes.cast(b64_encoded, ctypes.c_char_p).value.decode('utf-8')
    api.lsf_crypto_free(b64_encoded)
    api.lsf_crypto_free(crypto_error)

    return result

#-----------------------------------------------------------------------
def lsf_decrypt_RSA(api, b64_encoded):
    """
    lsf_read_key_MC_RSA_PKCS1
    lsf_base64_decode
    lsf_decrypt_MC_RSAOAEP_SHA256
    """

    crypto_error = ctypes.POINTER(LSF_ERROR_T)()

    rsa_decoded_private_key = ctypes.POINTER(ctypes.c_ubyte)()
    rsa_decoded_private_key_len = ctypes.c_int()
    r = api.lsf_read_key_MC_RSA_PKCS1(
                    LSF_PRIVATE_KEY_PATH.encode('utf-8'), 
                    LSF_RSA_PRIVATEKEY_TYPE, 
                    ctypes.byref(rsa_decoded_private_key), 
                    ctypes.byref(rsa_decoded_private_key_len), 
                    ctypes.byref(crypto_error)
                    )
    if r != LSF_CRYPTO_SUCCESS:
        api.lsf_crypto_free(rsa_decoded_private_key)
        errm = crypto_error.contents.message if crypto_error else NO_ERR_MSG
        api.lsf_crypto_free(crypto_error)
        raise Exception('lsf_read_key_MC_RSA_PKCS1:{}'.format(errm))

    b64_decoded = ctypes.POINTER(ctypes.c_ubyte)()
    b64_decoded_len = ctypes.c_int()
    r = api.lsf_base64_decode(
                            b64_encoded.encode('utf-8'),
                            len(b64_encoded),
                            ctypes.byref(b64_decoded),
                            ctypes.byref(b64_decoded_len),
                            ctypes.byref(crypto_error)
                            )
    if r != LSF_CRYPTO_SUCCESS:
        api.lsf_crypto_free(rsa_decoded_private_key)
        api.lsf_crypto_free(b64_decoded)
        errm = crypto_error.contents.message if crypto_error else NO_ERR_MSG
        api.lsf_crypto_free(crypto_error)
        raise Exception('lsf_base64_decode:{}'.format(errm))

    rsa_decrypted_text = ctypes.POINTER(ctypes.c_ubyte)()
    rsa_decrypted_text_len = ctypes.c_int()
    r = api.lsf_decrypt_MC_RSAOAEP_SHA256(
                                rsa_decoded_private_key,
                                rsa_decoded_private_key_len,
                                b64_decoded,
                                b64_decoded_len,
                                ctypes.byref(rsa_decrypted_text),
                                ctypes.byref(rsa_decrypted_text_len),
                                ctypes.byref(crypto_error)
                                )
    if r != LSF_CRYPTO_SUCCESS:
        api.lsf_crypto_free(rsa_decoded_private_key)
        api.lsf_crypto_free(b64_decoded)
        api.lsf_crypto_free(rsa_decrypted_text)
        errm = crypto_error.contents.message if crypto_error else NO_ERR_MSG
        api.lsf_crypto_free(crypto_error)
        raise Exception('lsf_decrypt_MC_RSAOAEP_SHA256:{}'.format(errm))

    api.lsf_crypto_free(rsa_decoded_private_key)
    api.lsf_crypto_free(b64_decoded)

    result = ctypes.cast(rsa_decrypted_text, ctypes.c_char_p).value.decode('utf-8')
    api.lsf_crypto_free(rsa_decrypted_text)
    api.lsf_crypto_free(crypto_error)

    return result

#-----------------------------------------------------------------------
def lsf_encrypt_ARIA(api, key, iv, plain_text):
    """
    lsf_encrypt_MC_ARIA_CBC_PKCS5
    lsf_base64_encode
    """

    crypto_error = ctypes.POINTER(LSF_ERROR_T)()

    aria_encrypted_text = ctypes.POINTER(ctypes.c_ubyte)()
    aria_encrypted_text_len = ctypes.c_int()

    r = api.lsf_encrypt_MC_ARIA_CBC_PKCS5(
                            key.encode('utf-8'),
                            iv.encode('utf-8'),
                            plain_text.encode('utf-8'),
                            ctypes.byref(aria_encrypted_text),
                            ctypes.byref(aria_encrypted_text_len),
                            ctypes.byref(crypto_error)
                            )
    if r != LSF_CRYPTO_SUCCESS:
        api.lsf_crypto_free(aria_encrypted_text)
        errm = crypto_error.contents.message if crypto_error else NO_ERR_MSG
        api.lsf_crypto_free(crypto_error)
        raise Exception('lsf_encrypt_MC_ARIA_CBC_PKCS5:{}'.format(errm))

    b64_encoded = ctypes.POINTER(ctypes.c_ubyte)()
    b64_encoded_len = ctypes.c_int()
    r = api.lsf_base64_encode(
                            aria_encrypted_text, 
                            aria_encrypted_text_len, 
                            ctypes.byref(b64_encoded),
                            ctypes.byref(b64_encoded_len),
                            ctypes.byref(crypto_error)
                            )
    if r != LSF_CRYPTO_SUCCESS:
        api.lsf_crypto_free(aria_encrypted_text)
        api.lsf_crypto_free(b64_encoded)
        errm = crypto_error.contents.message if crypto_error else NO_ERR_MSG
        api.lsf_crypto_free(crypto_error)
        raise Exception('lsf_base64_encode:{}'.format(errm))

    api.lsf_crypto_free(aria_encrypted_text)

    result = ctypes.cast(b64_encoded, ctypes.c_char_p).value.decode('utf-8')
    api.lsf_crypto_free(b64_encoded)
    api.lsf_crypto_free(crypto_error)

    print('KEY={} IV={}'.format(key, iv))
    return result

#-----------------------------------------------------------------------
def lsf_decrypt_ARIA(api, key, iv, b64_encoded):
    """
    lsf_base64_decode
    lsf_decrypt_MC_ARIA_CBC_PKCS5
    """

    crypto_error = ctypes.POINTER(LSF_ERROR_T)()

    b64_decoded = ctypes.POINTER(ctypes.c_ubyte)()
    b64_decoded_len = ctypes.c_int()
    r = api.lsf_base64_decode(
                            b64_encoded.encode('utf-8'),
                            len(b64_encoded),
                            ctypes.byref(b64_decoded),
                            ctypes.byref(b64_decoded_len),
                            ctypes.byref(crypto_error)
                            )
    if r != LSF_CRYPTO_SUCCESS:
        api.lsf_crypto_free(b64_decoded)
        errm = crypto_error.contents.message if crypto_error else NO_ERR_MSG
        api.lsf_crypto_free(crypto_error)
        raise Exception('lsf_base64_decode:{}'.format(errm))

    aria_plain_text = ctypes.POINTER(ctypes.c_ubyte)()
    aria_plain_text_len = ctypes.c_int()
    api.lsf_decrypt_MC_ARIA_CBC_PKCS5(
                            key.encode('utf-8'),
                            iv.encode('utf-8'),
                            b64_decoded,
                            b64_decoded_len,
                            ctypes.byref(aria_plain_text),
                            ctypes.byref(aria_plain_text_len), 
                            ctypes.byref(crypto_error)
                            )

    if r != LSF_CRYPTO_SUCCESS:
        api.lsf_crypto_free(b64_decoded)
        api.lsf_crypto_free(aria_plain_text)
        errm = crypto_error.contents.message if crypto_error else NO_ERR_MSG
        api.lsf_crypto_free(crypto_error)
        raise Exception('lsf_decrypt_MC_ARIA_CBC_PKCS5:{}'.format(errm))

    api.lsf_crypto_free(b64_decoded)

    result = ctypes.cast(aria_plain_text, ctypes.c_char_p).value.decode('utf-8')
    api.lsf_crypto_free(aria_plain_text)
    api.lsf_crypto_free(crypto_error)

    return result

#-----------------------------------------------------------------------
def lsf_magic_crypto_usable(api):
    """
    magic crypto usable
    """

    crypto_error = ctypes.POINTER(LSF_ERROR_T)()

    r = api.lsf_magic_crypto_usable(ctypes.byref(crypto_error))
    if r != 0:
        errm = crypto_error.contents.message if crypto_error else NO_ERR_MSG
        api.lsf_crypto_free(crypto_error)
        raise Exception('lsf_magic_crypto_usable:{}'.format(errm))

    api.lsf_crypto_free(crypto_error)

#-----------------------------------------------------------------------
if __name__ == '__main__':

    api = get_crypto_api()
    enc_m = lsf_encrypt_RSA(api, 'MESSAGE:hmkim')
    dec_m = lsf_decrypt_RSA(api, enc_m)
    print('dec_m={}'.format(dec_m))

    key = '12345678901234567890123456789012'
    iv = '1234567890123456'
    aria_enc_m = lsf_encrypt_ARIA(api, key, iv, 'SARABAL!')
    aria_dec_m = lsf_decrypt_ARIA(api, key, iv, aria_enc_m)
    print('aria_dec_m={}'.format(aria_dec_m))

