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
#define INVALID_SOCKET (-1)
#endif

#define BEE_VER_LEN     16

#define BEE_TRUE        1
#define BEE_FALSE       0

#define BEE_ID_LEN      64
#define BEE_IP_LEN      32

#define BEE_NAME_LEN    32
#define BEE_URL_LEN     256

#define BEE_SESS_LEN    128

#define BEE_SRV_TYPE    "ST_P2P"
#define BEE_SSDP_ST_LEN 64
#define BEE_SRV_PORT    5678
#define BEE_SRV_CLI     10      //max service client

#define BEE_LOCALHOST   "localhost"
#define BEE_CMD_LEN     32

#define BEE_TOPIC_LEN   128
#define BEE_KEEPALIVE   60

#define BEE_TIMEOUT_S   0
#define BEE_TIMEOUT_US  500*1000

#define BEE_LOCAL_TIMEO 100
#define BEE_PKT_SIZE    1500

#define BEE_MSG_SIZE    16*1024

#define bee_hexdump     noly_hexdump

/*! library status enum */
enum{
    BEE_INIT,                   /*!< library initial status */
    BEE_LOGINING,
    BEE_LOGIN,
    BEE_GET_INFO,
    BEE_GOT_INFO,
    BEE_CONNECTING,
    BEE_CONNECTED,
    BEE_DISCONNETED,
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
};
/**
 * @name    bee_get_version
 * @brief   get bee library version
 * @return  version string
 */
char *bee_get_version();
void bee_get_uid(char *uid);
int bee_user_init();
int bee_dev_init();
int bee_user_login_id_pw(char *id, char *pw);
int bee_user_login_cert(char *cert_path, char *pkey_path, char *pw);

int bee_dev_login_id_pw(char *id, char *pw);
int bee_dev_login_cert(char *cert_path, char *pkey_path, char *pw);
int bee_get_access_token(char *token);
int bee_set_service(char *api_key, char *api_sec);

int bee_logout();
int bee_destroy();

int bee_connect(char *id);
int bee_send_data(char *id, int cid, void *data, unsigned long len, int type);

int bee_log_level(int level);
int bee_log_to_file(int level, char *path);

int bee_add_user(char *user, char *dev_info, char *user_key);
int bee_del_user();
struct bee_nbr *bee_get_nbr_list();
int bee_discover_nbr();
int bee_delete_nbr_list();


int bee_reg_sm_cb(int (*callback)(void *data, int len));
int bee_reg_message_cb(int (*callback)(char *id, int cid, void *data, int len));
int bee_reg_status_cb(int (*status_cb)(int status));
int bee_reg_connection_cb(int (*conn_cb)(char *remote, int cid, int status));

void noly_hexdump(unsigned char *start, int len);

#endif
