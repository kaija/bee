#ifndef __BEE_H
#define __BEE_H
#include <pthread.h>
#include "sm_api.h"
#include "simclist.h"

#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif

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


#define BEE_TOPIC_LEN   128
#define BEE_KEEPALIVE   30

#define BEE_TIMEOUT_S   0
#define BEE_TIMEOUT_US  500*1000

#define BEE_PKT_SIZE    1500

#define BEE_MSG_SIZE    16*1024

enum{
    BEE_INIT,
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
    int                 (*msg_cb)(char *, void *, int);
    int                 (*sm_msg_cb)(void *, int);
    int                 (*sm_status_cb)(int status);
};
int bee_reg_status_cb(int (*status_cb)(int status));

#endif
