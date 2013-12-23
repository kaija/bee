#ifndef __BEE_H
#define __BEE_H
#include <pthread.h>
#include "sm_api.h"

#define BEE_ID_LEN      64
#define BEE_IP_LEN      32

#define BEE_NAME_LEN    32
#define BEE_URL_LEN     256

#define BEE_SESS_LEN    128

#define BEE_SRV_TYPE    "ST_P2P"
#define BEE_SSDP_ST_LEN 64

#define BEE_TOPIC_LEN   128

enum{
    BEE_API_OK,
    BEE_API_FAIL
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

struct sm_account {
    char                username[HTTP_USERNAME_LEN];
    char                password[HTTP_PASSWORD_LEN];
    char                certpath[HTTP_CA_PATH_LEN];
    char                pkeypath[HTTP_CA_PATH_LEN];
    char                pkeypass[HTTP_PASSWORD_LEN];
    char                session[SM_SESS_LEN];
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
    int                 keep_alive;
    int                 will;
    int                 (*msg_cb)(char *, void *, int);
    int                 (*sm_msg_cb)(void *, int);
};
struct bee_struct {
    pthread_t           bee_thread;
    struct sm_account   sm;
    struct mqtt_account mqtt;
    int                 type;   //user or dev
    int                 run;    //stop library run
    int                 status; //the library status
    char                ssdp_st[BEE_SSDP_ST_LEN];
};

#endif
