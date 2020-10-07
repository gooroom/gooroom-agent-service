#! /usr/bin/env python3

#-----------------------------------------------------------------------

#full path of config
CONFIG_PATH='/etc/gooroom/agent'
CONFIG_FULLPATH=CONFIG_PATH+'/Agent.conf'

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
T_DBUS='dbus'
T_MUSTOK='mustok'
T_LSF='lsf'

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

J_AGENT_STATUS='status'
J_AGENT_STATUS_RESULT='result'
J_AGENT_STATUS_RESULTCODE='resultCode'
J_AGENT_STATUS_MESSAGE='message'
J_AGENT_STATUS_PREV_ACCESS_DIFFTIME='prevAccessDiffTime'
J_AGENT_STATUS_VISA_STATUS='visaStatus'

J_AGENT_DATA='data'
J_AGENT_DATA_JOBNO='jobNo'
J_AGENT_DATA_CLIENTID='clientId'
J_AGENT_DATA_JOBDATA='job'

J_PKG='pkg_name'
J_STATUS='status'
J_OUTPUT='output'
J_MESSAGE='message'

J_TASK_DESC = 'task_desc'
J_TASK_TYPE = 'task_type'

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
SKEEP_SERVER_REQUEST='skeep_server_request'

#모듈이름이 아래와 같은 태스크는 모듈을 호출하지 않고
#agent가 태스크를 서버로 직접전송
MODULE_NAME_FOR_SERVER='SERVER'

#agent return code
AGENT_OK='200'
AGENT_NOK='111'
AGENT_DEFAULT_MESSAGE='OK'

#log limit size
LOG_TEXT_LIMIT=2048

#package operation timeout
PKCON_TIMEOUT_TEN_MINS=600
PKCON_TIMEOUT_FIVE_MINS=300
PKCON_TIMEOUT_DEFAULT=180
PKCON_TIMEOUT_ONCE=1

#syslog identifier
AGENT_SYSLOG_IDENTIFIER='gooroom-agent'

#journald log level
JOURNAL_EMERG=0
JOURNAL_ALERT=1
JOURNAL_CRIT=2
JOURNAL_ERR=3
JOURNAL_WARNNING=4
JOURNAL_NOTICE=5
JOURNAL_INFO=6
JOURNAL_DEBUG=7

#gooroom code in journald
GRMCODE_PASSWORD_CYCLE='990001'
GRMCODE_SCREEN_SAVER='990002'
GRMCODE_UPDATE_OPERATION_ENABLE='990003'
GRMCODE_UPDATE_OPERATION_DISABLE='990004'
GRMCODE_PASSWORD_CYCLE_LOCAL='990005'
GRMCODE_LOG_CONFIG_CHANGED='990006'
GRMCODE_HOMEFOLDER_OPERATION_ENABLE='990007'
GRMCODE_HOMEFOLDER_OPERATION_DISABLE='990008'
GRMCODE_JOURNAL_CONFIG_CHANGED='990009'
GRMCODE_ALERT_RELEASE='990010'
GRMCODE_CHANGE_BROWSER_POLICY='990100'
GRMCODE_CHANGE_MEDIA_POLICY='990101'
GRMCODE_JOB_RECEIVED='990201'
GRMCODE_JOB_PROC_OK='990202'
GRMCODE_JOB_PROC_NOK='990203'
GRMCODE_JOB_TRANS_OK='990204'
GRMCODE_JOB_TRANS_NOK='990205'
GRMCODE_POLLING_TIME='990300'
GRMCODE_HYPERVISOR='990301'
GRMCODE_CLIENT_POLICY='990302'
GRMCODE_HOMEFOLDER='990303'
GRMCODE_LOCAL_ACCOUNT='990304'
GRMCODE_REMOTE_ACCOUNT='990305'
GRMCODE_CLIENT_USER_POLICY='990306'
GRMCODE_UPDATER='990307'
GRMCODE_AGENT_CONNECTED='990308'
GRMCODE_AGENT_DISCONNECTED='990309'
GRMCODE_CLIENTJOB_SUCCESS='990310'
GRMCODE_CERTIFICATE='990311'
GRMCODE_APP_LIST='990312'
GRMCODE_PUSH_UPDATE='990313'

GRMCODE_SERVERJOB_STATUS='990999'

GRMCODE_NO_JOURNAL_DEFAULT='999999'

#notify-send
NOTI_DEFAULT_NAME='AGENT'

NOTI_INFO='info'
NOTI_ERR='error'

#prev access difftime
INIT_PREV_ACCESS_DIFFTIME=-1

#visa status
INIT_VISA_STATUS='denied'
VISA_STATUS_APPROVED='approved'
VISA_STATUS_DENIED='denied'

#polkit json file name
POLKIT_JSON_FILE_NAME='polkit.json'

#lsf path info
LSF_PUBLIC_INFO_PATH='/var/tmp/lsf/public/public_key.set'
LSF_POLICY_PATH='/var/tmp/lsf/private/whitelist.policy'

#lsf interlock 
LSF_INTERLOCK_PATH='/etc/gooroom/lsf/lsf.conf'
LSF_INTERLOCK_SECTION='MAIN'
LSF_INTERLOCK_KEY='interlock'
LSF_INTERLOCK_ON='on'
LSF_PHRASE= '0p7pqDJ1pN2UvBtF42qS5e8rLHaA+X2hp3N+uf02d10='
LSF_LIB_PATH= '/usr/lib/liblsf.so'

#lsf glyph
LSF_GLYPH_AUTH='?'
LSF_GLYPH_RELOAD='O'

#lsf log
LSF_MAX_APP_LOG_SIZE=10240
