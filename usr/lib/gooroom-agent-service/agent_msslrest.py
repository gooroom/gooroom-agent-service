#! /usr/bin/env python3

#-----------------------------------------------------------------------
import simplejson as json
import configparser
import httplib2
import datetime

from socket import timeout as SOCKET_TIMEOUT
from agent_util import AgentConfig, AgentLog, agent_format_exc
from agent_lsf_crypto import *
from agent_define import *
from agent_error import *
from agent_wscp import *
#-----------------------------------------------------------------------

class AgentMsslRest:
    """
    M-SSL RESTFUL
    """

    _token = None
    _crypto_api = None
    _wscp = None

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

        if not AgentMsslRest._token or expired:
            is_ok, status_code, err_msg = self.auth()
            if not is_ok:
                return None, status_code, err_msg

        rsp_headers, rsp_body = \
            self.shoot(rest_api, body, method, headers, need_new_http=need_new_http)

        http_status_code = rsp_headers['status']
        if '200' != http_status_code:
            err_msg = '!! request [http] status %s' % http_status_code
            self.logger.error(err_msg)
            return None, http_status_code, err_msg

        result = json.loads(rsp_body)
        agent_status = result[J_AGENT_STATUS]

        prev_access_difftime = ''
        if J_AGENT_STATUS_PREV_ACCESS_DIFFTIME in agent_status:
            prev_access_difftime = \
                agent_status[J_AGENT_STATUS_PREV_ACCESS_DIFFTIME]
            self.data_center.prev_access_difftime = prev_access_difftime

        agent_status_code = agent_status[J_AGENT_STATUS_RESULTCODE]
        if AGENT_OK == agent_status_code:
            err_msg = ''
            if J_AGENT_DATA in result:
                return result[J_AGENT_DATA], agent_status_code, None
            else:
                return [], agent_status_code, None
        else:
            if not expired and '401' == agent_status_code:
                return self.request(rest_api,
                    body, method, headers,
                    need_new_http=need_new_http, expired=True)
            else:
                err_msg = '!! request [agent] status %s' % agent_status_code
                self.logger.error(err_msg)
                return None, agent_status_code, err_msg

    def auth(self):
        """
        auth
        """

        body = {H_AUTH:{H_CID:self.data_center.get_client_id()}}

        rsp_headers, rsp_body = self.shoot(
            self.data_center.auth_api, body=json.dumps(body))

        http_status_code = rsp_headers['status']
        if '200' != http_status_code:
            err_msg = '!! auth [http] status %s' % http_status_code
            self.logger.error(err_msg)
            return False, http_status_code, err_msg

        result = json.loads(rsp_body)
        agent_status = result[J_AGENT_STATUS]
        agent_status_code = agent_status[J_AGENT_STATUS_RESULTCODE]
        if AGENT_OK != agent_status_code:
            err_msg = '!! auth [agent] status %s' % agent_status_code
            self.logger.error(err_msg)
            return False, agent_status_code, err_msg

        AgentMsslRest._token = rsp_headers[H_TOKEN]
        if AgentMsslRest._crypto_api:
            self.aria_key = AgentMsslRest._token[:32]
            self.aria_iv = AgentMsslRest._token[-16:]

        self.logger.debug('new token=%s' % AgentMsslRest._token)
        return True, AGENT_OK, None

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

        kcmvp_on_off = parser.get('certificate', 'kcmvp_on_off', fallback='off').lower()
        kcmvp_vendor = parser.get('certificate', 'kcmvp_vendor', fallback='unknown').lower()

        uri = 'https://%s%s' % (self.data_center.server_domain, rest_api)
        self.logger.debug('REQUEST=%s\n%s' % (uri, str(body)[:LOG_TEXT_LIMIT]))
        t = datetime.datetime.now().timestamp()
        try:
            if 'on' == kcmvp_on_off and body:
                body = {'enc_msg':body}
                if 'penta' == kcmvp_vendor:
                    if not self._wscp:
                        self._wscp = WrappedSCP(1024)
                    code, body['enc_msg'] = self._wscp.scp_encrypt(body['enc_msg'])
                    if code:
                        err_msg = '!! shoot [encrypt] status %d' % code
                        self.logger.error(err_msg)
                elif 'dream' == kcmvp_vendor and AgentMsslRest._crypto_api:
                    if rest_api == self.data_center.auth_api:
                        body['enc_msg'] = lsf_encrypt_RSA(
                                                        AgentMsslRest._crypto_api,
                                                        body['enc_msg'])
                    else:
                        body['enc_msg'] = lsf_encrypt_ARIA(
                                                        AgentMsslRest._crypto_api,
                                                        self.aria_key,
                                                        self.aria_iv,
                                                        body['enc_msg'])
                else:
                    err_msg = '!! shoot [encrypt] invalid vendor %s' % kcmvp_vendor
                    self.logger.error(err_msg)
                body = json.dumps(body)

            rsp_headers, rsp_body = agent_http.request(
                uri, method=method, headers=headers, body=body)

            if '200' == rsp_headers['status'] \
                and 'on' == kcmvp_on_off \
                and rsp_body:

                rsp_body = json.loads(rsp_body)
                if 'penta' == kcmvp_vendor:
                    if not self._wscp:
                        self._wscp = WrappedSCP(1024)
                    code, rsp_body = self._wscp.scp_decrypt(rsp_body['enc_msg'])
                    if code:
                        err_msg = '!! shoot [decrypt] status %d' % code
                        self.logger.error(err_msg)
                elif 'dream' == kcmvp_vendor \
                    and AgentMsslRest._crypto_api:
                    if self.data_center.auth_api == rest_api:
                        rsp_body = lsf_decrypt_RSA(
                                                AgentMsslRest._crypto_api,
                                                rsp_body['enc_msg'])
                        rsp_headers[H_TOKEN] = lsf_decrypt_RSA(
                                                AgentMsslRest._crypto_api,
                                                rsp_headers[H_TOKEN])
                    else:
                        rsp_body = lsf_decrypt_ARIA(
                                                AgentMsslRest._crypto_api,
                                                self.aria_key,
                                                self.aria_iv,
                                                rsp_body['enc_msg'])
                else:
                    err_msg = '!! shoot [decrypt] invalid vendor %s' % kcmvp_vendor
                    self.logger.error(err_msg)
        except SOCKET_TIMEOUT:
            self.data_center.increase_timeout_cnt()
            raise
        except httplib2.ServerNotFoundError:
            self.data_center.reload_server_domain()
            raise

        self.data_center.calc_max_response_time(datetime.datetime.now().timestamp() - t)
        self.logger.debug('RESPONSE=%s' % str(rsp_body)[:LOG_TEXT_LIMIT])

        return rsp_headers, rsp_body

