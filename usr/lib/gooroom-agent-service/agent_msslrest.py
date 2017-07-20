#! /usr/bin/env python3

#-----------------------------------------------------------------------
import httplib2
import simplejson as json

from agent_util import AgentConfig, AgentLog
from agent_define import *

#-----------------------------------------------------------------------
class AgentMsslRest:
    """
    M-SSL RESTFULL
    """

    _token = None

    def __init__(self, data_center):

        self.conf = AgentConfig.get_config()
        self.logger = AgentLog.get_logger()

        self.data_center = data_center

    def request(self, 
            rest_api, 
            body=None,
            method='POST', 
            headers={'Content-Type':'application/json; charset=utf-8'},
            expired=False):
        """
        request
        """

        #token
        if not AgentMsslRest._token or expired:
            is_ok, status_code, err_msg = self.auth()
            if not is_ok:
                return None, status_code, err_msg
            
        rsp_headers, rsp_body = self.shoot(rest_api, body, method, headers)

        #http status
        http_status_code = rsp_headers['status']
        if http_status_code != '200':
            err_msg = '!! request [http] status %s' % http_status_code
            self.logger.error(err_msg)
            return None, http_status_code, err_msg

        result = json.loads(rsp_body)
        agent_status = result[J_AGENT_STATUS]

        #agent status
        agent_status_code = agent_status[J_AGENT_STATUS_RESULTCODE]
        if agent_status_code == AGENT_OK:
            if J_AGENT_DATA in result:
                return result[J_AGENT_DATA], agent_status_code, ''
            else:
                return [], agent_status_code, ''

        else:
            #token expired
            if not expired and agent_status_code == '401':
                #ask for new token and resume
                return self.request(rest_api, body, method, headers, expired=True)
            else:
                err_msg = '!! request [agent] status %s' % agent_status_code
                self.logger.error(err_msg)
                return None, agent_status_code, err_msg

    def auth(self):
        """
        authenticate and get token
        """

        body = {H_AUTH:{H_CID:self.data_center.client_id}}

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
        self.logger.debug('new token=%s' % AgentMsslRest._token)
        return True, '200', None

    def shoot(self, 
            rest_api, 
            body=None,
            method='POST', 
            headers={'Content-Type':'application/json; charset=utf-8'}):
        """
        shoot
        """

        if self._token:
            headers[H_TOKEN] = AgentMsslRest._token

        uri = 'https://%s%s' % (self.data_center.server_domain, rest_api)
        self.logger.debug('REQUEST=%s\n%s' % (uri, str(body)[:LOG_TEXT_LIMIT]))
        rsp_headers, rsp_body = self.data_center.agent_http.request(uri, method=method, headers=headers, body=body)
        self.logger.debug('RESPONSE=%s' % str(rsp_body)[:LOG_TEXT_LIMIT])

        return rsp_headers, rsp_body

