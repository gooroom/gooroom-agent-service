#! /usr/bin/env python3

#-----------------------------------------------------------------------
import simplejson as json
import configparser
import httplib2
import datetime

from socket import timeout as SOCKET_TIMEOUT
from agent_util import AgentConfig, AgentLog,agent_format_exc
from agent_lsf_crypto import *
from agent_define import *
from agent_error import *

#-----------------------------------------------------------------------
class AgentMsslRest:
    """
    M-SSL RESTFULL
    """

    _token = None

    _crypto_api = None

    def __init__(self, data_center):

        self.conf = AgentConfig.get_config()
        self.logger = AgentLog.get_logger()

        self.data_center = data_center

        try:
            if not AgentMsslRest._crypto_api:
                AgentMsslRest._crypto_api = get_crypto_api()
        except:
            AgentMsslRest._crypto_api = None
            self.logger.error(agent_format_exc())

    def request(self, 
            rest_api, 
            body=None,
            method='POST', 
            headers={'Content-Type':'application/json; charset=utf-8'},
            need_new_http=True,
            expired=False):
        """
        request
        """

        #token
        if not AgentMsslRest._token or expired:
            is_ok, status_code, err_msg = self.auth()
            if not is_ok:
                return None, status_code, err_msg
            
        rsp_headers, rsp_body = \
            self.shoot(rest_api, body, method, headers, need_new_http=need_new_http)

        #http status
        http_status_code = rsp_headers['status']
        if http_status_code != '200':
            err_msg = '!! request [http] status %s' % http_status_code
            self.logger.error(err_msg)
            return None, http_status_code, err_msg

        result = json.loads(rsp_body)
        agent_status = result[J_AGENT_STATUS]

        #check to be prevAccessDiffTime value or not
        prev_access_difftime = ''
        if J_AGENT_STATUS_PREV_ACCESS_DIFFTIME in agent_status:
            prev_access_difftime = \
                agent_status[J_AGENT_STATUS_PREV_ACCESS_DIFFTIME]
            self.data_center.prev_access_difftime = prev_access_difftime

        #check visa status
        visa_status = ''
        if J_AGENT_STATUS_VISA_STATUS in agent_status:
            visa_status = \
                agent_status[J_AGENT_STATUS_VISA_STATUS]
            if visa_status:
                self.data_center.visa_status = visa_status

        #agent status
        agent_status_code = agent_status[J_AGENT_STATUS_RESULTCODE]
        if agent_status_code == AGENT_OK:
            err_msg = ''

            if J_AGENT_DATA in result:
                return result[J_AGENT_DATA], agent_status_code, None
            else:
                return [], agent_status_code, None
        else:
            #token expired
            if not expired and agent_status_code == '401':
                #ask for new token and resume
                return self.request(rest_api, 
                    body, method, headers, 
                    need_new_http=need_new_http, expired=True)
            else:
                err_msg = '!! request [agent] status %s' % agent_status_code
                self.logger.error(err_msg)
                return None, agent_status_code, err_msg

    def auth(self):
        """
        authenticate and get token
        """

        body = {H_AUTH:{H_CID:self.data_center.get_client_id()}}

        rsp_headers, rsp_body = self.shoot(
            self.data_center.auth_api, body=json.dumps(body))

        #http status 
        http_status_code = rsp_headers['status']
        if http_status_code != '200':
            err_msg = '!! auth [http] status %s' % http_status_code
            self.logger.error(err_msg)
            return False, http_status_code, err_msg

        result = json.loads(rsp_body)
        agent_status = result[J_AGENT_STATUS]

        #agent status
        agent_status_code = agent_status[J_AGENT_STATUS_RESULTCODE]
        if agent_status_code != AGENT_OK:
            err_msg = '!! auth [agent] status %s' % agent_status_code
            self.logger.error(err_msg)
            return False, agent_status_code, err_msg

        AgentMsslRest._token = rsp_headers[H_TOKEN]
        if AgentMsslRest._crypto_api:
            self.aria_key = AgentMsslRest._token[:32]
            self.aria_iv = AgentMsslRest._token[-16:]

        self.logger.debug('new token=%s' % AgentMsslRest._token)
        return True, '200', None

    def shoot(self, 
            rest_api, 
            body=None,
            method='POST', 
            headers={'Content-Type':'application/json; charset=utf-8'},
            need_new_http=True):
        """
        shoot
        """

        if not self.data_center.server_domain:
            self.data_center.server_domain = self.data_center.read_server_domain()

        agent_http = None

        if need_new_http:
            agent_http = self.data_center.create_httplib2_http()
        else:
            agent_http = self.data_center.agent_http

        if self._token:
            headers[H_TOKEN] = AgentMsslRest._token

        parser = configparser.RawConfigParser()
        parser.optionxform = str
        parser.read('/etc/gooroom/gooroom-client-server-register/gcsr.conf')
        headers['agent_client_id'] = parser.get('certificate', 'client_name')

        #KCMVP
        try:
            kcmvp_on_off = parser.get('certificate', 'kcmvp_on_off').lower()
        except:
            kcmvp_on_off = 'off'

        uri = 'https://%s%s' % (self.data_center.server_domain, rest_api)
        self.logger.debug('REQUEST=%s\n%s' % (uri, str(body)[:LOG_TEXT_LIMIT]))
        t = datetime.datetime.now().timestamp()
        try:
            #print('NORMAL headers={}\nbody={}'.format(headers, body))
            if kcmvp_on_off == 'on' \
                and AgentMsslRest._crypto_api \
                and body:
                #ENCRYPT
                body = {'enc_msg':body}
                if rest_api == self.data_center.auth_api:
                    #RSA
                    body['enc_msg'] = lsf_encrypt_RSA(
                                                    AgentMsslRest._crypto_api,
                                                    body['enc_msg'])
                else:
                    #ARIA
                    body['enc_msg'] = lsf_encrypt_ARIA(
                                                    AgentMsslRest._crypto_api,
                                                    self.aria_key, 
                                                    self.aria_iv, 
                                                    body['enc_msg'])
                body = json.dumps(body)
            
            #print('ENC headers={}\nbody={}'.format(headers, body))
            rsp_headers, rsp_body = agent_http.request(
                uri, method=method, headers=headers, body=body)

            if rsp_headers['status'] == '200' \
                and kcmvp_on_off == 'on' \
                and AgentMsslRest._crypto_api \
                and rsp_body:

                rsp_body = json.loads(rsp_body)
                #print('RSP={}'.format(rsp_body))

                #DECRYPT
                if rest_api == self.data_center.auth_api:
                    #RSA
                    rsp_body = lsf_decrypt_RSA(
                                            AgentMsslRest._crypto_api,
                                            rsp_body['enc_msg'])
                    #print('***** headers={}'.format(rsp_headers))
                    rsp_headers[H_TOKEN] = lsf_decrypt_RSA(
                                            AgentMsslRest._crypto_api,
                                            rsp_headers[H_TOKEN])
                else:
                    #ARIA
                    rsp_body = lsf_decrypt_ARIA(
                                            AgentMsslRest._crypto_api,
                                            self.aria_key, 
                                            self.aria_iv, 
                                            rsp_body['enc_msg'])
                #print('(R) headers={}\nbody={}'.format(rsp_headers, rsp_body))

        except SOCKET_TIMEOUT:
            self.data_center.increase_timeout_cnt()
            raise
        except httplib2.ServerNotFoundError:
            #단말이 재등록되어 grm url이 변경되었을 경우
            self.data_center.reload_server_domain()
            raise

        self.data_center.calc_max_response_time(datetime.datetime.now().timestamp() - t)
        self.logger.debug('RESPONSE=%s' % str(rsp_body)[:LOG_TEXT_LIMIT])

        return rsp_headers, rsp_body

