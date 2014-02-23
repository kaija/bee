/**
 * @file    bee_internal.h
 * @brief   bee real time message library
 * @author  Kevin Chang kevin_chang@gemteks.com
 * @date    2014/01/03
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

#define BEE_LIB_CMD_LEN     32

#define BEE_LIB_P2P_VER     1
#define BEE_LIB_MSG_VER     1
#define BEE_LIB_SM_VER      1

#ifndef BEE_LIB_VERSION
#define BEE_LIB_VERSION     2
#endif

#ifndef BEE_LIB_BUILD_NUM
#define BEE_LIB_BUILD_NUM   1
#endif


#define BEE_PKT_HDR_MAGIC   0xff
#define BEE_PKT_VER         0x01

struct bee_client{
    int                 type;
    char                uid[SM_UID_LEN];
    int                 fd;
    //Add some struct here
};

struct bee_pkt_header{
    uint8_t             header;
    uint8_t             version;
    uint8_t             opt;
    uint16_t            csum;
    uint32_t            length;
}BEE_PKT_HDR;

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
    struct bee_version  version;
    int                 mode;
    pthread_t           bee_thread;
    pthread_mutex_t     api_lock;
    struct sm_account   sm;
    struct mqtt_account mqtt;
    struct ssdp_profile ssdp;
    struct local_serv   local;
    struct bee_nbr      *nbr;
    int                 type;   //user or dev
    int                 run;    //stop library run
    int                 status; //the library status
    int                 error;  //error code
    int                 event_port;
    int                 event_sock;
    int                 (*msg_cb)(void *, char *,int,  void *, int);
    int                 (*sm_msg_cb)(void *, void *, int);
    int                 (*status_cb)(void *, int status);
    int                 (*error_cb)(void *, int code);
    int                 (*send_cb)(void *, char *remote, int cid, int status);
    int                 (*recv_cb)(void *, char *remote, int cid, int status);
    int                 (*disconn_cb)(void *, char *remote, int cid, int reason);
    void                (*app_cb)(void *);
    void                (*ver_cb)(char *src, struct bee_version *ver);
    int                 app_timeout;
};

void *bee_main(void *data);
int bee_init(void *ctx, int type);
int bee_login(int type);
int bee_mqtt_start();
int bee_ssdp_update();
char *bee_get_ssdp_st();
int bee_message_handler(char *src, char *data);
int bee_sm_message_handler(char *tlv, unsigned long tlv_len);
int bee_conn_message_handler(char *src, char *data, int len);
int bee_event_handler(int sock);
int bee_send_conn_req(char *id);
int bee_send_disconect(char *id, int type);
int bee_init_without_thread(void *ctx, int type);
void *bee_cli_seek(char *id, int fd);
int bee_local_connect(char *ip, int port);
int bee_local_safe_send(int fd, void *data, unsigned long len);
int bee_client_add(char *id, int fd);
int bee_client_del(char *id, int fd);
struct bee_client *bee_client_get(char *id, int fd);
int bee_cli_id_seeker(const void *e, const void *id);
int bee_cli_fd_seeker(const void *e, const void *id);
int bee_error_handler(int code);
void bee_disconnect_cb(char *remote, int cid, int reason);
int bee_lib_ver_parser(char *json, struct bee_version *version);
int bee_lib_message_handler(char *src, char *data, int len);
int bee_status_change_handler_internal(const char *func, int status);
int bee_safe_message_cb(char *id, int cid, void *data, int len);
void bee_init_guest_uid();

#define bee_status_change_handler(status) bee_status_change_handler_internal(__func__,status)

#endif
