#! /usr/bin/env python3

#-----------------------------------------------------------------------

#full path of config
CONFIG_FULLPATH='/etc/gooroom/agent/Agent.conf'

#WORKER
WORKER_GOT_FIRED='go home buddy...'

#모듈템플릿 엘리먼트 태그명
T_MOD='module'
T_MODN='module_name'
T_DESC='desc'
T_PARAM='param'
T_TASK='task'
T_TASKN='task_name'

T_IN='in'
T_OUT='out'
T_COL='col'

T_REQUEST='request'
T_RESPONSE='response'

T_SIMPLETYPE='simpleType'
T_SIMPLETYPE_ENUM='enum'
T_RESTRICTION='restriction'

#모듈템플릿 속성명
T_NAME='name'
T_TYPE='type'
T_TEST='test'
T_HIDDEN='hidden'
T_CHOOSE='choose'
T_WHEN='when'
T_OTHER='otherwise'
T_MANDATORY='mandatory'
T_POLLTIME='polltime'
T_SEQ='seq'
T_VALUE='value'
T_BOOTABLE='bootable'
T_PRIORITY='priority'
T_ID='id'

#agent와 server가 송수신하는 job에 대한 json의 키값
J_OB='job'
J_OBS='jobs'
J_MOD=T_MOD
J_MODN=T_MODN
J_TASK=T_TASK
J_TASKN=T_TASKN
J_IN=T_IN
J_OUT=T_OUT
J_REQUEST=T_REQUEST
J_RESPONSE=T_RESPONSE
J_ID=T_ID
J_SEQ=T_SEQ

J_AGENT_STATUS='agentStatus'
J_AGENT_STATUS_RESULT='result'
J_AGENT_STATUS_RESULTCODE='resultCode'
J_AGENT_STATUS_MESSAGE='message'

J_AGENT_DATA='agentData'
J_AGENT_DATA_JOBNO='jobNo'
J_AGENT_DATA_CLIENTID='clientId'
J_AGENT_DATA_JOBDATA='job'

J_PKG='pkg_name'
J_STATUS='status'
J_OUTPUT='output'
J_ERR_REASON='error_reason'

#IN HEADER
H_TOKEN='gooroom-client-token'
H_AUTH='auth'
H_CID='client_id'
H_CERT='gooroom-client-cert'

#TEMPLATE EXTENTION
T_EXT='tmpl'

#AGENT 식별자
SERVERJOB='SERVERJOB'
CLIENTJOB='CLIENTJOB'

#DBUS
DBUS_NAME='dbus_name'
DBUS_OBJ='dbus_obj'
DBUS_IFACE='dbus_iface'

#TASK TYPE
S_TO_A='S_TO_A'
A_TO_S='A_TO_S'
A_TO_M='A_TO_M'
D_TO_M='D_TO_M'
D_TO_S='D_TO_S'
D_TO_D='D_TO_D'

#CLIENTJOB을 호출하는 3주체
AGENT_CALL=0
SERVER_CALL=1
DBUS_CALL=2

#모듈의 결과값을 서버로 전송하지 않기 위해서
#모듈이 아래값을 반환하면 agent는 결과를 서버로 전송하지 않음
SKEEP_SERVER_REQUEST='!! module do not want to request to server'

#모듈이름이 아래와 같은 태스크는 모듈을 호출하지 않고
#agent가 태스크를 서버로 직접전송
MODULE_NAME_FOR_SERVER='SERVER'

#agent return code
AGENT_OK='200'
AGENT_NOK='111'

LOG_TEXT_LIMIT=2048
