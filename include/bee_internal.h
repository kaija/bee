/**
 * @file	bee_internal.h
 * @brief 	bee real time message library
 * @author 	Kevin Chang kevin_chang@gemteks.com
 * @date	2014/01/03
 */

#ifndef __BEE_INTERNAL_H
#define __BEE_INTERNAL_H
#include <pthread.h>
#include "bee.h"
#include "sm_api.h"
#include "simclist.h"

#define BEE_LIB_PAUSE       "pause"
#define BEE_LIB_RESUME      "resume"
#define BEE_LIB_RECONNECT   "resume"
#define BEE_LIB_DESTROY     "destroy"

#define BEE_MODE_THREAD     1
#define BEE_MODE_NOTHREAD   0

#define BEE_PAUSE           2

struct bee_client{
    int                 type;
    char                uid[SM_UID_LEN];
    int                 fd;
    //Add some struct here
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
    void                *ctx;
    char                version[BEE_VER_LEN];
    int                 mode;
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
    int                 (*msg_cb)(void *, char *,int,  void *, int);
    int                 (*sm_msg_cb)(void *, void *, int);
    int                 (*status_cb)(void *, int status);
    int                 (*conn_cb)(void *, char *remote, int cid, int status);
    void                (*app_cb)(void *);
    int                 app_timeout;
};
#endif
