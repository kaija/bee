/**
 * @file	bee.h
 * @brief 	bee real time message library
 * @author 	Kevin Chang kevin_chang@gemteks.com
 * @date	2014/01/03
 */

#ifndef __BEE_H
#define __BEE_H
#include <pthread.h>
#include "sm_api.h"
#include "simclist.h"

#ifndef INVALID_SOCKET
#define INVALID_SOCKET          (-1)
#endif

#define BEE_VER_LEN             16

#define BEE_TRUE                1
#define BEE_FALSE               0

#define BEE_ID_LEN              64
#define BEE_IP_LEN              32

#define BEE_NAME_LEN            32
#define BEE_URL_LEN             256

#define BEE_SESS_LEN            128

#define BEE_SRV_TYPE            "ST_P2P"
#define BEE_SSDP_ST_LEN         64
#define BEE_SRV_PORT            5678
#define BEE_SRV_CLI             10
#define BEE_SSDP_INTERVAL       10      // ssdp update interval

#define BEE_LOCALHOST           "localhost"
#define BEE_CMD_LEN             32

#define BEE_TOPIC_LEN           128
#define BEE_KEEPALIVE           60

#define BEE_TIMEOUT_S           0
#define BEE_TIMEOUT_US          500*1000

#define BEE_LOCAL_TIMEO         100
#define BEE_PKT_SIZE            1500

#define BEE_MSG_SIZE            16*1024

#define bee_hexdump             noly_hexdump

#define BEE_DATA_TYPE_RELIABLE    SM_MSG_TYPE_DEFAULT
#define BEE_DATA_TYPE_REALTIME    SM_MSG_TYPE_RT

/*! library status enum */
enum{
    BEE_INIT,                   /*!< library initial status */
    BEE_LOGINING,
    BEE_LOGIN,
    BEE_GET_INFO,
    BEE_GOT_INFO,
    BEE_CONNECTING,
    BEE_CONNECTED,
    BEE_DISCONNECTED,
    BEE_ERROR
};

enum{
    BEE_SOCKET_ERROR,
    BEE_SSDP_ERROR,
    BEE_NOT_LOGIN,
    BEE_OOM
};
enum{
    BEE_CONN_REJECT,    //Message connection reject
    BEE_CONN_ACCEPT,     //Message connection accept
    BEE_CONN_REQUEST,
    BEE_CONN_DISCONN
};
enum{
    BEE_API_OK,
    BEE_API_FAIL,
    BEE_API_TIMEOUT,
    BEE_API_NOT_LOGIN,
    BEE_API_PARAM_ERROR
};

struct bee_nbr
{
    char                id[BEE_ID_LEN];
    char                ip[BEE_IP_LEN];
    char                name[BEE_NAME_LEN];
    struct bee_nbr      *next;
};

struct bee_user_list{
    char                **user_list;
    int                 user_num;
};

struct bee_client{
    int local;
    int fd;
};

struct sm_account {
    char                username[HTTP_USERNAME_LEN];
    char                password[HTTP_PASSWORD_LEN];
    char                certpath[HTTP_CA_PATH_LEN];
    char                pkeypath[HTTP_CA_PATH_LEN];
    char                pkeypass[HTTP_PASSWORD_LEN];
    char                session[SM_SESS_LEN];
    char                uid[SM_UID_LEN];
    char                api_key[SM_API_KEY_LEN];
    char                api_sec[SM_API_SEC_LEN];
};

struct mqtt_account {
    struct mosquitto    *mosq;
    char                username[HTTP_USERNAME_LEN];
    char                password[HTTP_PASSWORD_LEN];
    int                 security;
    char                topic[BEE_TOPIC_LEN];
    char                server[BEE_IP_LEN];
    int                 port;
    int                 clean_sess;
    int                 qos;
    int                 debug;
    int                 retain;
    int                 keepalive;
    int                 will;
    int                 sock;
};

struct ssdp_profile {
    char                ssdp_st[BEE_SSDP_ST_LEN];
    int                 sock;
};

struct local_serv {
    int                 sock;
    int                 port;
    list_t              client;
};

struct bee_struct {
    char                version[BEE_VER_LEN];
    pthread_t           bee_thread;
    pthread_mutex_t     api_lock;
    struct sm_account   sm;
    struct mqtt_account mqtt;
    struct ssdp_profile ssdp;
    struct local_serv   local;
    int                 type;   //user or dev
    int                 run;    //stop library run
    int                 status; //the library status
    int                 error;  //error code
    int                 event_port;
    int                 event_sock;
    int                 (*msg_cb)(char *,int,  void *, int);
    int                 (*sm_msg_cb)(void *, int);
    int                 (*status_cb)(int status);
    int                 (*conn_cb)(char *remote, int cid, int status);
    void                (*app_cb)();
    int                 app_timeout;
};
/**
 * @name    bee_get_version
 * @brief   get bee library version
 * @return  version string
 */
char *bee_get_version();
/**
 * @name    bee_get_uid
 * @brief   get account uid
 * @param   uid     the uid buffer
 * @param   len     the buffer length
 */
void bee_get_uid(char *uid, int len);

/**
 * @name    bee_set_uid
 * @brief   set account uid
 * @param   uid     the uid buffer
 */
void bee_set_uid(char *uid);
/**
 * @name    bee_user_init
 * @brief   initial the library for user type use
 * @retval  0       success
 * @retval  <0      error with error code
 */
int bee_user_init_v2();
/**
 * @name    bee_user_init_v2
 * @brief   initial the library for user type use and no thread created
 * @retval  0       success
 * @retval  <0      error with error code
 */
int bee_user_init();
/**
 * @name    bee_dev_init
 * @brief   initial the library for device type use
 * @retval  0       success
 * @retval  <0      error with error code
 */
int bee_dev_init();
/**
 * @name    bee_dev_init_v2
 * @brief   initial the library for device type use and no thread created
 * @retval  0       success
 * @retval  <0      error with error code
 */
int bee_dev_init_v2();

/**
 * @name    bee_user_login_id_pw
 * @brief   login cloud with user's id/ pw
 * @param   id      the account id
 * @param   pw      the account password
 * @retval  0       success
 * @retval  <0      error with error code
 */
int bee_user_login_id_pw(char *id, char *pw);

/**
 * @name    bee_user_login_cert
 * @brief   user login cloud with certificate
 * @param   cert_path the certificate path
 * @param   pkey_path the private key path
 * @param   pw        the private key password
 * @retval  0       success
 * @retval  <0      error with error code
 */
int bee_user_login_cert(char *cert_path, char *pkey_path, char *pw);

/**
 * @name    bee_dev_login_id_pw
 * @brief   login cloud with device's id/ pw
 * @param   id      the account id
 * @param   pw      the account password
 * @retval  0       success
 * @retval  <0      error with error code
 */
int bee_dev_login_id_pw(char *id, char *pw);

/**
 * @name    bee_dev_login_cert
 * @brief   device login cloud with certificate
 * @param   cert_path the certificate path
 * @param   pkey_path the private key path
 * @param   pw        the private key password
 * @retval  0       success
 * @retval  <0      error with error code
 */
int bee_dev_login_cert(char *cert_path, char *pkey_path, char *pw);

/**
 * @name    bee_loop_forever
 * @brief   start connect to server.
 * @retval  0       success
 * @retval  <0      error with error code
 */
int bee_loop_forever();

/**
 * @name    bee_get_access_token
 * @brief   get cloud access token
 * @param   token     the token buffer
 * @retval  0       success
 * @retval  <0      error with error code
 */
int bee_get_access_token(char *token, int len);

/**
 * @name    bee_set_service
 * @brief   set the cloud service type
 * @param   api_key the cloud service api key
 * @param   api_sec the cloud service api secret
 * @retval  0       success
 * @retval  <0      error with error code
 */
int bee_set_service(char *api_key, char *api_sec);

/**
 * @name    bee_logout
 * @brief   logout the from cloud service
 * @retval  0       success
 * @retval  <0      error with error code
 */
int bee_logout();

/**
 * @name    bee_destroy
 * @brief   logout service and destroy all.
 * @retval  0       success
 * @retval  <0      error with error code
 */
int bee_destroy();

/**
 * @name    bee_connect
 * @brief   connect to remote user/device
 * @param   id      the remote user/device id
 * @retval  0       success
 * @retval  <0      error with error code
 */
int bee_connect(char *id);
/**
 * @name    bee_send_data
 * @brief   send data to remote user/device
 * @param   id      the remote user/device id
 * @param   cid     local connection id
 * @param   data    the data buffer
 * @param   len     the data buffer length
 * @param   type    the send type  BEE_DATA_TYPE_RELIABLE  /  BEE_DATA_TYPE_REALTIME
 * @retval  0       success
 * @retval  <0      error with error code
 */
int bee_send_data(char *id, int cid, void *data, unsigned long len, int type);

/**
 * @name    bee_log_level
 * @brief   change the log display level.
 * @param   level   the log level  PLOG_LEVEL_DEBUG -> PLOG_LEVEL_FATAL
 * @retval  0       success
 * @retval  <0      error with error code
 */
int bee_log_level(int level);

/**
 * @name    bee_log_to_file
 * @brief   log to file.
 * @param   level   the log level  PLOG_LEVEL_DEBUG -> PLOG_LEVEL_FATAL
 * @param   path    the log path
 * @retval  0       success
 * @retval  <0      error with error code
 */
int bee_log_to_file(int level, char *path);

/**
 * @name    bee_add_user
 * @brief   device add user to allow list
 * @param   user    the remote user id (uid)
 * @param   dev_info
 * @param   user_key    the shared key between user and device
 * @retval  0       success
 * @retval  <0      error with error code
 */
int bee_add_user(char *user, char *dev_info, char *user_key);

/**
 * @name    bee_del_user
 * @brief   delete user from device.
 * @param   user    the remote user id (uid)
 * @retval  0       success
 * @retval  <0      error with error code
 */
int bee_del_user(char *user);

/**
 * @name    bee_get_nbr_list
 * @brief   get neighbor list from SSDP
 * @retval  0       success
 * @retval  <0      error with error code
 */
struct bee_nbr *bee_get_nbr_list();

/**
 * @name    bee_discover_nbr
 * @brief   send a neighbor discover.
 * @retval  0       success
 * @retval  <0      error with error code
 */
int bee_discover_nbr();

/**
 * @name    bee_delete_nbr_list
 * @brief   delete neighbor list
 * @retval  0       success
 * @retval  <0      error with error code
 */
int bee_delete_nbr_list();


/**
 * @name    bee_reg_sm_cb
 * @brief   register service manager message callback
 * @param   callback callback function
 * @retval  0       success
 * @retval  <0      error with error code
 */
int bee_reg_sm_cb(int (*callback)(void *data, int len));
/**
 * @name    bee_reg_app_cb
 * @brief   register a user defined callback
 * @param   callback    the callback function
 * @param   timeout     the time interval between callback.
 * @retval  0       success
 * @retval  <0      error with error code
 */
int bee_reg_app_cb(void (*callback)(), int timeout);
/**
 * @name    bee_reg_message_cb
 * @brief   register data message callback
 * @param   callback the callback function for data message
 * @retval  0       success
 * @retval  <0      error with error code
 */
int bee_reg_message_cb(int (*callback)(char *id, int cid, void *data, int len));
/**
 * @name    bee_reg_status_cb
 * @brief   register library status change callback
 * @param   callback    the status change callback
 * @retval  0       success
 * @retval  <0      error with error code
 */
int bee_reg_status_cb(int (*status_cb)(int status));
/**
 * @name    bee_reg_connection_cb
 * @brief   register data connection callback
 * @param   conn_cb     the connection status callback.
 * @retval  0       success
 * @retval  <0      error with error code
 */
int bee_reg_connection_cb(int (*conn_cb)(char *remote, int cid, int status));

/**
 * @name    noly_hexdump
 * @brief   hex dump function for debug
 * @param   start   the pointer to the data
 * @param   len     the data length
 * @retval  0       success
 * @retval  <0      error with error code
 */
void noly_hexdump(unsigned char *start, int len);

#endif
