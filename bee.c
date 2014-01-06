/**
 * @file	bee.c
 * @brief 	bee real time message library
 * @author 	Kevin Chang kevin_chang@gemteks.com
 * @date	2014/01/03
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <netinet/in.h>
#include <net/if.h>

#include "mosquitto.h"
#include "mosquitto_internal.h"

#include "bee.h"
#include "utils.h"
#include "lssdp.h"
#include "log.h"
#include "simclist.h"

static struct bee_struct bee = {
    .run = BEE_FALSE,
    .mqtt.mosq = NULL,
    .mqtt.sock = -1,
    .mqtt.security = 0,
    .local.sock = 0,
    .sm_msg_cb = NULL,
    .msg_cb = NULL,
    .app_cb = NULL,
    .app_timeout = 0,
};
void *bee_main(void *data);
int bee_init(int type);
int bee_login(int type);
int bee_mqtt_start();
int bee_ssdp_update();
int bee_message_handler(char *src, char *data);
int bee_sm_message_handler(char *tlv, unsigned long tlv_len);
int bee_status_change_handler(int status);
int bee_conn_message_handler(char *src, char *data, int len);
int bee_send_conn_req(char *id);
int bee_init_without_thread(int type);
/* ===============================================
 *     Mosquitto callback area
 */
void bee_mqtt_connect_callback(struct mosquitto *mosq, void *obj, int result)
{
    if(!result){
        mosquitto_subscribe(mosq, NULL, bee.mqtt.topic, bee.mqtt.qos);
    }else{
        fprintf(stderr, "%s\n", mosquitto_connack_string(result));
        PLOG(PLOG_LEVEL_ERROR,"%s", mosquitto_connack_string(result));
    }
}

void bee_mqtt_subscribe_callback(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos)
{
    bee_status_change_handler(BEE_CONNECTED);
    PLOG(PLOG_LEVEL_INFO,"Subscribed (mid: %d): %d\n", mid, granted_qos[0]);
}

void bee_mqtt_log_callback(struct mosquitto *mosq, void *obj, int level, const char *str)
{
    if(str) PLOG(PLOG_LEVEL_DEBUG,"%s\n", str);
}

void bee_mqtt_message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
    PLOG(PLOG_LEVEL_DEBUG, "%s\n", message->payload);
    //mosquitto_message_free(message);
    //{"serial":450024072,"src":"700000165","type":5,"version":"1.0"}
    char src[SM_UID_LEN];
    if(strstr(message->payload, "content") != NULL){//push notify
        char *data = malloc(message->payloadlen);
        if(data){
            memset(data, 0, message->payloadlen);
            if(json_str_get_obj(message->payload, "content", data, message->payloadlen) == 0 ){
                if(json_str_get_obj(message->payload, "src", src, SM_UID_LEN) == 0 ){
                    bee_message_handler(src, data);
                }
            }
            free(data);
        }else{
            PLOG(PLOG_LEVEL_ERROR, "Out of memory\n");
        }
    }else if(strstr(message->payload, "serial") != NULL){//send and get
        char serial[16];
        if(json_str_get_obj(message->payload, "serial", serial, 16) == 0){
            unsigned long srl = atoi(serial);
            printf("get serial %ld\n", srl);
            char *json = sm_get_msg(bee.sm.session, bee.sm.api_key, srl -1 );
            if(json){
                int len = strlen(json);
                char *data = malloc(len);
                memset(data, 0, len);
                if(json_str_get_obj(json, "content", data, len) == 0 ){
                    if(json_str_get_obj(json, "src", src, SM_UID_LEN) == 0 ){
                        bee_message_handler(src, data);
                    }
                }
            }
        }
    }else{
        PLOG(PLOG_LEVEL_DEBUG,"Drop unknown message\n");
    }
}
void bee_mqtt_disconnect_callback(struct mosquitto *mosq, void *obj, int err)
{
    PLOG(PLOG_LEVEL_INFO, "MQTT disconnect\n");
    bee_status_change_handler(BEE_DISCONNECTED);
}
int bee_mqtt_start()
{
    int rc = 0;
    PLOG(PLOG_LEVEL_INFO,"MQTT connecting to %s:%d\n", bee.mqtt.server, bee.mqtt.port);
    bee.mqtt.mosq = mosquitto_new(bee.mqtt.username, bee.mqtt.clean_sess, &bee);
    if(!bee.mqtt.mosq) {
        switch (errno){
            case ENOMEM:
                PLOG(PLOG_LEVEL_FATAL, "Out of memory\n");
                break;
            case EINVAL:
                PLOG(PLOG_LEVEL_FATAL, "Invalid ID and / or clean session\n");
                break;
        }
        goto err;
    }
    mosquitto_log_callback_set(bee.mqtt.mosq, bee_mqtt_log_callback);
    if(bee.mqtt.security){
        if(mosquitto_username_pw_set(bee.mqtt.mosq, bee.mqtt.username, bee.mqtt.password) != 0){
            goto err;
        }
    }
    mosquitto_connect_callback_set(bee.mqtt.mosq, bee_mqtt_connect_callback);
    mosquitto_message_callback_set(bee.mqtt.mosq, bee_mqtt_message_callback);
    mosquitto_subscribe_callback_set(bee.mqtt.mosq, bee_mqtt_subscribe_callback);
    mosquitto_disconnect_callback_set(bee.mqtt.mosq, bee_mqtt_disconnect_callback);
    rc = mosquitto_connect(bee.mqtt.mosq, bee.mqtt.server, bee.mqtt.port, bee.mqtt.keepalive);
    if(rc){
        if(rc == MOSQ_ERR_ERRNO){
            PLOG(PLOG_LEVEL_ERROR, "%s\n", strerror(errno));
        }else{
            PLOG(PLOG_LEVEL_ERROR, "Unable to connect (%d)\n",rc);
            goto err;
        }
    }
    return 0;
err:
    mosquitto_lib_cleanup();
    mosquitto_destroy(bee.mqtt.mosq);
    bee.mqtt.mosq = NULL;
    return -1;
}
int bee_mqtt_handler(fd_set *rfs, fd_set *wfs)
{
    int rc = 0;
    int max_packets = 1;
    struct mosquitto *mosq = bee.mqtt.mosq;
    int sock = mosquitto_socket(mosq);
    if(FD_ISSET(sock, rfs)){
        rc = mosquitto_loop_read(mosq, max_packets);
        if(rc || sock == INVALID_SOCKET){
            return rc;
        }
    }
    if(FD_ISSET(sock, wfs)){
        rc = mosquitto_loop_write(mosq, max_packets);
        if(rc || sock == INVALID_SOCKET){
            return rc;
        }
    }
    return mosquitto_loop_misc(mosq);
}
/* ===============================================
 * BEE config function
 */
char *bee_get_version()
{
    sprintf(bee.version, "%s", BEE_VERSION);
    return bee.version;
}

void bee_get_uid(char *uid, int len)
{
    if(uid) strncpy(uid, bee.sm.uid ,len);
}

void bee_set_uid(char *uid)
{
    if(uid) strncpy(bee.sm.uid , uid,SM_UID_LEN);
}

int bee_log_level(int level)
{
    return BEE_API_OK;
}

int bee_log_to_file(int level, char *path)
{
    return BEE_API_OK;
}

/* ===============================================
 * BEE user related function
 */
int bee_add_user(char *user, char *dev_info, char *user_key)
{
    int ret = 0;
    if(user_key){
        ret = sm_add_user(bee.sm.session, user, NULL, bee.sm.api_key, bee.sm.api_sec, user_key);
    }else{
        ret = sm_add_user(bee.sm.session, user, NULL, bee.sm.api_key, bee.sm.api_sec, "false");
    }
    if(ret == 0)
        return BEE_API_OK;
    else
        return BEE_API_FAIL;
}

int bee_del_user(char *user)
{
    //TODO
    return BEE_API_OK;
}

struct bee_nbr *bee_get_nbr_list()
{
    //TODO
    return NULL;
}

int bee_discover_nbr()
{
    //TODO
    return BEE_API_OK;
}

int bee_delete_nbr_list()
{
    //TODO
    return BEE_API_OK;
}

/* ===============================================
 * BEE library main function
 */
int bee_set_service(char *api_key, char *api_sec)
{
    if(!api_key || !api_sec) return BEE_API_PARAM_ERROR;
    strncpy(bee.sm.api_key, api_key, SM_API_KEY_LEN - 1);
    strncpy(bee.sm.api_sec, api_sec, SM_API_SEC_LEN - 1);
    return BEE_API_OK;
}

int bee_user_init()
{
    bee_init(SM_TYPE_USER);
    return BEE_API_OK;
}

int bee_user_init_v2()
{
    bee_init_without_thread(SM_TYPE_USER);
    return BEE_API_OK;
}

int bee_dev_init()
{
    bee_init(SM_TYPE_DEVICE);
    return BEE_API_OK;
}

int bee_dev_init_v2()
{
    bee_init_without_thread(SM_TYPE_DEVICE);
    return BEE_API_OK;
}

int bee_default_conn_cb(char *remote, int cid, int status)
{
    if(remote){
        PLOG(PLOG_LEVEL_INFO, "Accept remote %s connection by default\n", remote);
    }
    return BEE_CONN_ACCEPT;
}

int bee_init_without_thread(int type)
{

    list_init(&bee.local.client);
    plogger_set_path("/tmp/p2p.log");
    plogger_enable_file(PLOG_LEVEL_INFO);
    plogger_enable_screen(PLOG_LEVEL_DEBUG);
    bee.type = type;
    bee.mqtt.will = BEE_FALSE;
    bee.mqtt.qos = 1;
    bee.status = BEE_INIT;
    bee.mqtt.debug = BEE_TRUE;
    bee.mqtt.retain = 0;
    bee.mqtt.keepalive = BEE_KEEPALIVE; // Default 60 sec keepalive
    bee.mqtt.clean_sess = BEE_TRUE;
    bee.conn_cb = bee_default_conn_cb;
    if(pthread_mutex_init(&bee.api_lock, NULL) != 0){
        PLOG(PLOG_LEVEL_ERROR, "API lock init error\n");
    }
    if(bee.ssdp.sock == 0){
        lssdp_get_iface(NULL);
        bee.ssdp.sock = lssdp_create_socket();
        if(bee.ssdp.sock < 0) {
            bee.error = BEE_SSDP_ERROR;
            return BEE_API_FAIL;
        }
    }
    if(bee.local.sock == 0){
        bee.local.sock = noly_tcp_socket(BEE_SRV_PORT, BEE_SRV_CLI);
        if(bee.local.sock < 0){
            bee.error = BEE_SOCKET_ERROR;
            PLOG(PLOG_LEVEL_ERROR,"Local socket create failure (%d)%s\n", errno, strerror(errno));
            return BEE_API_FAIL;
        }
        PLOG(PLOG_LEVEL_INFO, "Local Service Socket created %d\n", BEE_SRV_PORT);
    }
    return BEE_API_OK;
}
int bee_loop_forever()
{
    bee.run = BEE_TRUE;
    bee_main((void *) &bee);
    return BEE_API_OK;
}
int bee_init(int type)
{
    list_init(&bee.local.client);
    plogger_set_path("/tmp/p2p.log");
    plogger_enable_file(PLOG_LEVEL_INFO);
    plogger_enable_screen(PLOG_LEVEL_INFO);
    bee.type = type;
    bee.mqtt.will = BEE_FALSE;
    bee.mqtt.qos = 1;
    bee.status = BEE_INIT;
    bee.mqtt.debug = BEE_TRUE;
    bee.mqtt.retain = 0;
    bee.mqtt.keepalive = BEE_KEEPALIVE; // Default 60 sec keepalive
    bee.mqtt.clean_sess = BEE_TRUE;
    bee.conn_cb = bee_default_conn_cb;
    if(pthread_mutex_init(&bee.api_lock, NULL) != 0){
        PLOG(PLOG_LEVEL_ERROR, "API lock init error\n");
    }
    if(bee.ssdp.sock == 0){
        lssdp_get_iface(NULL);
        bee.ssdp.sock = lssdp_create_socket();
        if(bee.ssdp.sock < 0) {
            bee.error = BEE_SSDP_ERROR;
            return BEE_API_FAIL;
        }
    }
    if(bee.local.sock == 0){
        bee.local.sock = noly_tcp_socket(BEE_SRV_PORT, BEE_SRV_CLI);
        if(bee.local.sock < 0){
            bee.error = BEE_SOCKET_ERROR;
            PLOG(PLOG_LEVEL_ERROR,"Local socket create failure (%d)%s\n", errno, strerror(errno));
            return BEE_API_FAIL;
        }
        PLOG(PLOG_LEVEL_INFO, "Local Service Socket created %d\n", BEE_SRV_PORT);
    }
    //first time run a thread
    if(bee.run == BEE_FALSE){
        bee.run = BEE_TRUE;
        if(pthread_create(&bee.bee_thread, NULL, bee_main, (void *)&bee) != 0){
            PLOG(PLOG_LEVEL_FATAL, "Main thread create failure\n");
        }
        PLOG(PLOG_LEVEL_INFO, "Main thread started.\n");
    }
    return BEE_API_OK;
}

int bee_user_login_id_pw(char *id, char *pw)
{
    if(!id || !pw) return BEE_API_PARAM_ERROR;
    strncpy(bee.sm.username, id, HTTP_USERNAME_LEN);
    strncpy(bee.sm.password, pw, HTTP_PASSWORD_LEN);
    bee_login(SM_TYPE_USER);
    bee.type = SM_TYPE_USER;
    return BEE_API_OK;
}

int bee_user_login_cert(char *cert_path, char *pkey_path, char *pw)
{
    if(!cert_path || !pkey_path || !pw) return BEE_API_PARAM_ERROR;
    strncpy(bee.sm.certpath, cert_path, HTTP_CA_PATH_LEN);
    strncpy(bee.sm.pkeypath, pkey_path, HTTP_CA_PATH_LEN);
    strncpy(bee.sm.pkeypass, pw, HTTP_PASSWORD_LEN);
    bee_login(SM_TYPE_USER);
    bee.type = SM_TYPE_USER;
    return BEE_API_OK;
}
int bee_dev_login_id_pw(char *id, char *pw)
{
    if(!id || !pw) return BEE_API_PARAM_ERROR;
    strncpy(bee.sm.username, id, HTTP_USERNAME_LEN);
    strncpy(bee.sm.password, pw, HTTP_PASSWORD_LEN);
    bee_login(SM_TYPE_DEVICE);
    bee.type = SM_TYPE_DEVICE;
    return BEE_API_OK;
}

int bee_dev_login_cert(char *cert_path, char *pkey_path, char *pw)
{
    if(!cert_path || !pkey_path || !pw) return BEE_API_PARAM_ERROR;
    strncpy(bee.sm.certpath, cert_path, HTTP_CA_PATH_LEN);
    strncpy(bee.sm.pkeypath, pkey_path, HTTP_CA_PATH_LEN);
    strncpy(bee.sm.pkeypass, pw, HTTP_PASSWORD_LEN);
    bee_login(SM_TYPE_DEVICE);
    bee.type = SM_TYPE_DEVICE;
    return BEE_API_OK;
}

int bee_get_msg_info()
{
    struct msg_service_info info;
    if(sm_get_msg_info(bee.type, bee.sm.session, &info) == 0){
        strncpy(bee.mqtt.username, info.mqtt_id, HTTP_USERNAME_LEN);
        strncpy(bee.mqtt.password, info.mqtt_pw, HTTP_PASSWORD_LEN);
        strncpy(bee.mqtt.server, info.mqtt_ip, HTTP_IP_LEN);
        bee.mqtt.port = info.mqtt_port;
        //FIXME topic get from cloud?
        sprintf(bee.mqtt.topic, "client/%s/%s-HA", bee.mqtt.username, bee.mqtt.username);
        PLOG(PLOG_LEVEL_INFO, "MQTT info\nIP:%s\nPort:%d\nID:%s\nPW:%s\n", bee.mqtt.server, bee.mqtt.port, bee.mqtt.username, bee.mqtt.password);
        bee.status = BEE_GOT_INFO;
        return BEE_API_OK;
    }
    return BEE_API_FAIL;
}

int bee_login(int type){
    int ret = 0;
    bee.status = BEE_LOGINING;
    if(type == SM_TYPE_USER){
        ret = sm_login(SM_LOGIN_IDPW, bee.sm.username, bee.sm.password, bee.sm.certpath, bee.sm.pkeypath, bee.sm.session, bee.sm.uid);
    }else{
        ret = sm_dev_login(SM_LOGIN_IDPW, bee.sm.username, bee.sm.password, bee.sm.certpath, bee.sm.pkeypath, bee.sm.session, bee.sm.uid);
    }
    if(ret != 0){
        PLOG(PLOG_LEVEL_WARN, "Login service manager error %d\n", ret);
        bee.status = BEE_INIT;
        return BEE_API_FAIL;
    }
    bee.status = BEE_GET_INFO;
    if(bee_get_msg_info() != BEE_API_OK){
        bee.status = BEE_LOGIN;
    }
    return BEE_API_OK;
}
int bee_get_access_token(char *token, int len)
{
    if(strlen(bee.sm.session) > 0){
        strncpy(token, bee.sm.session ,len);
        return BEE_API_OK;
    }
    return BEE_API_FAIL;
}
int bee_logout()
{
    PLOG(PLOG_LEVEL_INFO, "Logout\n");
    return BEE_API_OK;
}

int bee_destroy()
{
    PLOG(PLOG_LEVEL_INFO, "Destroy\n");
    bee.run = BEE_FALSE;
    noly_udp_sender(BEE_LOCALHOST, bee.event_port, "disconn", strlen("disconn"));
    return BEE_API_OK;
}

int bee_connect(char *id)
{
    int ret = BEE_API_OK;
    //FIXME add local tcp socket handle
    ret = bee_send_conn_req(id);
    return ret;
}

int bee_send_message(char *id, void *data, unsigned long len, int type)
{
    int ret = BEE_API_NOT_LOGIN;
    if(strlen(bee.sm.session) == 0) return BEE_API_NOT_LOGIN;
    size_t out_len;
    char *b64 = base64_encode(data, len, &out_len);
    if(b64){
        ret = sm_send_msg(bee.sm.session ,id, bee.sm.api_key, b64, type);
        free(b64);
    }
    return ret;
}

int bee_send_data(char *id, int cid, void *data, unsigned long len, int type)
{
    if(!data || len == 0) return BEE_API_PARAM_ERROR;
    //FIXME add local tcp socket case
    unsigned char *tlv = malloc(len + 8);
    if(tlv){
        tlv[0] = 0x00;
        tlv[1] = 0x01;
        tlv[2] = 0x00;
        tlv[3] = 0x00;
        tlv[4] = (int) ((len>>24) & 0xff);
        tlv[5] = (int) ((len>>16) & 0xff);
        tlv[6] = (int) ((len>>8) & 0xff);
        tlv[7] = (int) ((len) & 0xff);
        memcpy(&tlv[8] , data, len);
        //noly_hexdump(tlv, 8 + len );
        bee.error = bee_send_message(id, tlv, len + 8, type);
        free(tlv);
    }
    return BEE_API_OK;
}

int bee_mqtt_send(char *id, void *data, int len)
{
    size_t sz;
    char *b64 = base64_encode(data, len, &sz);
    if(b64){
        char json[1024];
        int klen = sprintf(json, "{\"content\":\"%s\",\"src\":\"%s\"}", b64, bee.sm.uid);
        char topic[256];
        sprintf(topic, "client/%s/%s-HA", id, id);
        mosquitto_publish(bee.mqtt.mosq, NULL, topic, klen, json, 0, 0);
        free(b64);
    }
    return 0;
}

int bee_send_p2p(char *id, void *data, unsigned long len)
{
    if(!data || len == 0) return BEE_API_PARAM_ERROR;
    unsigned char *tlv = malloc(len + 8);
    if(tlv){
        tlv[0] = 0x00;
        tlv[1] = 0x02;
        tlv[2] = 0x00;
        tlv[3] = 0x00;
        tlv[4] = (int) ((len>>24) & 0xff);
        tlv[5] = (int) ((len>>16) & 0xff);
        tlv[6] = (int) ((len>>8) & 0xff);
        tlv[7] = (int) ((len) & 0xff);
        memcpy(&tlv[8] , data, len);
        //noly_hexdump(tlv, 8 + len );
        bee.error = bee_send_message(id, tlv, len + 8, SM_MSG_TYPE_RT);
        //bee_mqtt_send(NULL, tlv, len + 8);//for test
        free(tlv);
    }
    return BEE_API_OK;
}

int bee_send_conn_req(char *id)
{
    char data[128];
    int len = snprintf(data, 128, "{\"cmd\":\"conn_req\",\"type\":\"msg\",\"src\":\"%s\"}", bee.sm.uid);
    unsigned char *tlv = malloc(len + 8);
    if(tlv){
        tlv[0] = 0x00;
        tlv[1] = 0x05;
        tlv[2] = 0x00;
        tlv[3] = 0x00;
        tlv[4] = (int) ((len>>24) & 0xff);
        tlv[5] = (int) ((len>>16) & 0xff);
        tlv[6] = (int) ((len>>8) & 0xff);
        tlv[7] = (int) ((len) & 0xff);
        memcpy(&tlv[8] , data, len);
        //noly_hexdump(tlv, 8 + len );
        bee.error = bee_send_message(id, tlv, len + 8, SM_MSG_TYPE_RT);
        free(tlv);
    }
    return BEE_API_OK;
}
int bee_send_conn_resp(char *id, int resp)
{
    char data[128];
    int len = 0; 
    if(resp == BEE_CONN_ACCEPT){
        len = snprintf(data, 128, "{\"cmd\":\"conn_resp\",\"type\":\"msg\",\"src\":\"%s\", \"result\":\"accept\"}", bee.sm.uid);
    }else{
        len = snprintf(data, 128, "{\"cmd\":\"conn_resp\",\"type\":\"msg\",\"src\":\"%s\", \"result\":\"reject\"}", bee.sm.uid);
    }
    unsigned char *tlv = malloc(len + 8);
    if(tlv){
        tlv[0] = 0x00;
        tlv[1] = 0x05;
        tlv[2] = 0x00;
        tlv[3] = 0x00;
        tlv[4] = (int) ((len>>24) & 0xff);
        tlv[5] = (int) ((len>>16) & 0xff);
        tlv[6] = (int) ((len>>8) & 0xff);
        tlv[7] = (int) ((len) & 0xff);
        memcpy(&tlv[8] , data, len);
        //noly_hexdump(tlv, 8 + len );
        bee.error = bee_send_message(id, tlv, len + 8, SM_MSG_TYPE_RT);
        free(tlv);
    }
    return BEE_API_OK;
}
int bee_message_handler(char *src, char *data)
{
    if(!src || !data) return BEE_API_PARAM_ERROR;
    PLOG(PLOG_LEVEL_DEBUG,"%s\n%s\n", src, data);
    size_t tlv_len;
    char *tlv = base64_decode(data, strlen(data), &tlv_len);
    if(tlv){
        unsigned long len = (tlv[4] << 24) + (tlv[5] << 16) + (tlv[6] << 8) + tlv[7];
        if(len != tlv_len - 8) {
            PLOG(PLOG_LEVEL_WARN, "TLV data length not match!!!\n");
        }
        PLOG(PLOG_LEVEL_DEBUG, "Get TLV data length:%d\n", len);
        //noly_hexdump((unsigned char *)tlv, 16);
        if(tlv[1] == 0x01){//Data
            memmove(&tlv[0], &tlv[8], len);
            tlv[len] = '\0';
            if(bee.msg_cb){
                bee.msg_cb(src, -1, tlv, len);
            }
            //noly_hexdump((unsigned char *)tlv, 8);
        }else if(tlv[1] == 0x00){//SM
            memmove(&tlv[0], &tlv[8], len);
            tlv[len] = '\0';
            bee_sm_message_handler(tlv, len);
            //noly_hexdump((unsigned char *)tlv, 16);
        }else if(tlv[1] == 0x05){//Message type connection
            bee_conn_message_handler(src, &tlv[8], len);
        }else{//P2P connection use
            PLOG(PLOG_LEVEL_INFO,"Bee library not support P2P mode reply something\n");
            //char reply[] = "{\"cmd\":\"conn_reject\",\"reason\":\"not support\"}";
            //bee_send_p2p(src, reply, strlen(reply));
        }
        free(tlv);
    }
    return BEE_API_OK;
}

int bee_conn_message_handler(char *src, char *data, int len)
{
    PLOG(PLOG_LEVEL_INFO, "Recv message connection request %s\n", data);
    char cmd[BEE_CMD_LEN];
    if(json_str_get_obj(data, "cmd", cmd, BEE_CMD_LEN) == 0){
        if(strncmp(cmd, "conn_req",strlen("conn_req"))==0){
            if(bee.conn_cb(src, -1, BEE_CONN_REQUEST) == BEE_CONN_ACCEPT){
                bee_send_conn_resp(src, BEE_CONN_ACCEPT);
            }else{
                bee_send_conn_resp(src, BEE_CONN_REJECT);
            }
        }else if(strncmp(cmd, "conn_resp",strlen("conn_resp"))==0){
            if(json_str_get_obj(data, "result", cmd, BEE_CMD_LEN) == 0){
                if(strncmp(cmd, "accept",strlen("accept"))==0){
                    bee.conn_cb(src, -1, BEE_CONN_ACCEPT);
                }else{
                    bee.conn_cb(src, -1, BEE_CONN_REJECT);
                }
            }
        }
    }
    return BEE_API_OK;
}

int bee_reg_app_cb(void (*callback)(), int timeout)
{
    if(callback){
        bee.app_timeout = timeout;
        bee.app_cb = callback;
    }else{
        bee.app_timeout = 0;
        bee.app_cb = NULL;
    }
    return BEE_API_OK;
}

int bee_reg_sm_cb(int (*callback)(void *data, int len))
{
    if(!callback) return BEE_API_PARAM_ERROR;
    bee.sm_msg_cb = callback;
    return BEE_API_OK;
}

int bee_sm_message_handler(char *tlv, unsigned long tlv_len)
{
    if(!tlv || tlv_len < 1) return BEE_API_PARAM_ERROR;
    tlv[tlv_len] = '\0';
    PLOG(PLOG_LEVEL_INFO, "Recv Service Manager Command: %s\n", tlv);
    if(bee.sm_msg_cb){
        return bee.sm_msg_cb(tlv,tlv_len);
    }else{
        PLOG(PLOG_LEVEL_INFO, "Service Manager command callback not registered\n");
    }
    return 0;
}
int bee_reg_message_cb(int (*callback)(char *id, int cid, void *data, int len))
{
    bee.msg_cb = callback;
    return BEE_API_OK;
}

void bee_check()
{
    if(bee.status == BEE_GOT_INFO && bee.mqtt.mosq == NULL)
    {
        if(bee_mqtt_start() == 0){
            bee.status = BEE_CONNECTING;
            bee.mqtt.sock = mosquitto_socket(bee.mqtt.mosq);
        }
    }else if(bee.status == BEE_LOGIN){
        if(strlen(bee.mqtt.server) == 0){
            PLOG(PLOG_LEVEL_INFO,"MQTT info not get\n");
            bee_get_msg_info();
        }
    }else if(bee.status == BEE_CONNECTING){
            PLOG(PLOG_LEVEL_INFO,"MQTT still connecting\n");
    }
}

int bee_local_cli_add(int fd)
{
    struct bee_client *client = malloc(sizeof(struct bee_client));
    if(client){
        client->fd = fd;
        client->local = BEE_TRUE;
        list_append(&bee.local.client, client);
        return 0;
    }
    PLOG(PLOG_LEVEL_ERROR, "Out of memory\n");
    return -1;
}
int bee_local_cli_seeker(const void *e, const void *id)
{
    const struct bee_client *client = (struct bee_client *)e;
    if(client->fd == *(int *)id ){
        return 1;
    }
    return 0;
}
int bee_local_cli_del(int fd)
{
    int sock = fd;
    PLOG(PLOG_LEVEL_INFO,"delete client fd %d\n", fd);
    list_attributes_seeker(&bee.local.client, bee_local_cli_seeker);
    void *cli = list_seek(&bee.local.client, &sock);
    if(cli){
        list_delete(&bee.local.client, cli);
    }
    return 0;
}

int bee_local_safe_read(int fd, unsigned long timeout)//timeout in ms
{
    char *data = NULL;
    int ret, len, total = 0;
    char buf[BEE_PKT_SIZE];
    struct timeval tv;
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;
    fd_set fs;
    while(1){
        FD_ZERO(&fs);
        FD_SET(fd, &fs);
        ret = select(fd+1, &fs, NULL, NULL, &tv );
        if(ret == 0){
            break;//Timeout break
        }else if(ret > 0){
            memset(buf, 0, BEE_PKT_SIZE);
            len = read(fd, buf, BEE_PKT_SIZE-1);
            if(len > 0){
                data = realloc(data, total + len);
                if(data){
                    memcpy(data + total, buf, len);
                }else{
                    PLOG(PLOG_LEVEL_ERROR, "Out of Memory\n");
                }
                total += len;
            }else{
                //FIXME Error handle. Remote disconnect
            }
        }
    }
    if(total) printf("%s\n", buf);
    return total;
}


int bee_local_cli_handle(fd_set *fs)
{
    int size = list_size(&bee.local.client);
    int i = 0;
    for(i=0;i<size;i++){
        struct bee_client *client = list_get_at(&bee.local.client, i);
        if(client && FD_ISSET(client->fd, fs)){
            int len = bee_local_safe_read(client->fd, BEE_LOCAL_TIMEO);
            if(len > 0){
            }else{
                int fd = client->fd;
                bee_local_cli_del(fd);
                close(fd);
            }
        }
    }
    return 0;
}
int bee_local_cli_fd_set(fd_set *fs)
{
    int max = 0;
    int size = list_size(&bee.local.client);
    int i = 0;
    for(i=0;i<size;i++){
        struct bee_client *client = list_get_at(&bee.local.client, i);
        if(client && client->fd > 0){
            FD_SET(client->fd, fs);
            max = MAX(max, client->fd);
        }
    }
    return max;
}

int bee_local_serv_handle(int sock)
{
    struct sockaddr_in cli;
    socklen_t cli_len;
    int fd = accept(sock, (struct sockaddr *)&cli, &cli_len);
    if(fd > 0){
        PLOG(PLOG_LEVEL_INFO,"accept new client fd %d\n", fd);
        noly_socket_set_nonblock(fd);
        bee_local_cli_add(fd);
        bee_local_safe_read(fd, BEE_LOCAL_TIMEO);
        //FIXME Add status callback
    }else{
        PLOG(PLOG_LEVEL_ERROR,"accept connection error (%d)%s\n", errno, strerror(errno));
    }
    return 0;
}

int bee_reg_status_cb(int (*status_cb)(int status))
{
    bee.status_cb = status_cb;
    return 0;
}
int bee_reg_connection_cb(int (*conn_cb)(char *remote, int cid, int status))
{
    bee.conn_cb = conn_cb;
    return 0;
}
int bee_status_change_handler(int status)
{
    if(status == BEE_CONNECTED){
        bee.status = BEE_CONNECTED;
    }
    if(bee.status_cb){
        bee.status_cb(status);
    }
    return 0;
}
int bee_network_update()
{
    bee_ssdp_update();
    return BEE_API_OK;
}
int bee_ssdp_update()
{
    if(strlen(bee.ssdp.ssdp_st) > 0){
        lssdp_set_service(bee.ssdp.ssdp_st, bee.sm.username, bee.sm.uid, BEE_SRV_PORT, "P2P");
        lssdp_delete_list(bee.ssdp.ssdp_st);
        lssdp_request_service(bee.ssdp.ssdp_st);
    }else{
        lssdp_set_service(BEE_SRV_TYPE, bee.sm.username, bee.sm.uid, BEE_SRV_PORT, "P2P");
        lssdp_delete_list(BEE_SRV_TYPE);
        lssdp_request_service(BEE_SRV_TYPE);
    }
    return BEE_API_OK;
}
int bee_ssdp_set_st(char *st)
{
    if(st){
        strncpy(bee.ssdp.ssdp_st, st, BEE_SSDP_ST_LEN);
        return BEE_API_OK;
    }
    return BEE_API_PARAM_ERROR;
}
int bee_ssdp_handler(int sock)
{
    struct sockaddr_in sender;
    socklen_t sender_len;
    char pkt[SSDP_MAX_PKT_LEN];
    size_t pkt_len;
    memset(pkt, '\0', sizeof(pkt));
    sender_len = sizeof(struct sockaddr_in);
    pkt_len = recvfrom(sock, pkt, sizeof(pkt), 0, (struct sockaddr *)&sender, &sender_len);
    if(pkt_len > 0){
        lssdp_process_packet(sock, (struct sockaddr *)&sender, pkt, pkt_len);
    }
    return 0;
}
void *bee_main(void *data)
{
    time_t app_next_timeout = 0, now = time(NULL);
    time_t ssdp_timeout = time(NULL) + BEE_SSDP_INTERVAL;
    struct timeval tv;
    fd_set rfs,wfs;
    int max = 0;
    int event_port;
    int event_sock = noly_udp_rand_socket(&event_port);
    if(event_sock < 0){
        PLOG(PLOG_LEVEL_ERROR, "local notify socket create failure\n");
    }
    bee.event_port = event_port;
    bee.event_sock = event_sock;
    PLOG(PLOG_LEVEL_INFO, "Local event socket port %d\n", event_port);
    while(bee.run)
    {
        tv.tv_sec = BEE_TIMEOUT_S;
        tv.tv_usec = BEE_TIMEOUT_US;
        FD_ZERO(&rfs);
        FD_ZERO(&wfs);
        if(bee.event_sock > 0) {
            FD_SET(bee.event_sock, &rfs);
            max = MAX(bee.event_sock, max);
        }
        if(bee.local.sock > 0) {
            FD_SET(bee.local.sock, &rfs);
            max = MAX(bee.local.sock, max);
        }
        if(bee.ssdp.sock > 0) {
            FD_SET(bee.ssdp.sock, &rfs);
            max = MAX(bee.ssdp.sock, max);
        }
        if((bee.status == BEE_CONNECTED || bee.status == BEE_CONNECTING)&& (bee.mqtt.sock = mosquitto_socket(bee.mqtt.mosq)) > 0){
            FD_SET(bee.mqtt.sock, &rfs);
            struct mosquitto *mosq = bee.mqtt.mosq;
            if(mosq->out_packet || mosq->current_out_packet){
                FD_SET(bee.mqtt.sock, &wfs);
            }
            max = MAX(bee.mqtt.sock, max);
        }
        if(bee.app_cb && bee.app_timeout > 0){//for user register callback
            now = time(NULL);
            if(app_next_timeout != 0 && now >= app_next_timeout){
                bee.app_cb();
                app_next_timeout = now + bee.app_timeout;
            }else if(app_next_timeout == 0){
                app_next_timeout = now + bee.app_timeout;
            }
        }
        max = MAX(max, bee_local_cli_fd_set(&rfs));// add local client socket
        int ret = select(max+1, &rfs, &wfs, NULL, &tv);
        if(ret == 0){
            now = time(NULL);
            PLOG(PLOG_LEVEL_DEBUG, "Periodically check\n");
            bee_check();
            if (bee_mqtt_handler(&rfs, &wfs) != MOSQ_ERR_SUCCESS){
                mosquitto_reconnect(bee.mqtt.mosq);
            }
            if(now > ssdp_timeout){
                bee_ssdp_update();
                ssdp_timeout = now + BEE_SSDP_INTERVAL;
            }
        }else if(ret < 0){
            PLOG(PLOG_LEVEL_ERROR, "socket select error %d (%s)\n", ret , strerror(errno));
            if(bee.local.sock > 0 && FD_ISSET(bee.local.sock, &rfs)){
                close(bee.local.sock);
                bee.local.sock = 0;
                PLOG(PLOG_LEVEL_ERROR, "local socket error\n");
            }
            if(bee.mqtt.sock > 0 && FD_ISSET(bee.mqtt.sock, &rfs)){
                close(bee.mqtt.sock);
                bee.mqtt.sock = 0;
                PLOG(PLOG_LEVEL_ERROR, "MQTT socket error\n");
            }
            if(bee.event_sock > 0 && FD_ISSET(bee.event_sock, &rfs)){
                close(bee.event_sock);
                bee.event_sock = 0;
                PLOG(PLOG_LEVEL_ERROR, "event socket error\n");
            }
            bee_local_cli_handle(&rfs);
            //return 0;
        }else{
            if(bee.event_sock > 0 && FD_ISSET(bee.event_sock, &rfs)){
                PLOG(PLOG_LEVEL_DEBUG, "event socket select\n");
            }
            if(bee.ssdp.sock > 0 && FD_ISSET(bee.ssdp.sock, &rfs)){
                PLOG(PLOG_LEVEL_DEBUG, "SSDP socket select\n");
                bee_ssdp_handler(bee.ssdp.sock);
            }
            bee_mqtt_handler(&rfs, &wfs);
            if(bee.local.sock > 0 && FD_ISSET(bee.local.sock, &rfs)){
                PLOG(PLOG_LEVEL_DEBUG, "Local client socket connected %d\n", bee.local.sock);
                bee_local_serv_handle(bee.local.sock); 
            }
            bee_local_cli_handle(&rfs);
            //TODO check socket one by one
        }
    }
    PLOG(PLOG_LEVEL_DEBUG, "Library thread end\n");
    if(bee.event_sock > 0) {
        close(bee.event_sock);
        bee.event_sock = 0;
    }
    if(bee.local.sock > 0) {
        close(bee.local.sock);
        bee.local.sock = 0;
    }
    if(bee.ssdp.sock > 0) {
        close(bee.ssdp.sock);
        bee.ssdp.sock = 0;
    }
    if(bee.mqtt.mosq) {
        mosquitto_disconnect(bee.mqtt.mosq);
        mosquitto_lib_cleanup();
        mosquitto_destroy(bee.mqtt.mosq);
    }
    PLOG(PLOG_LEVEL_INFO, "Library thread stopped\n");
    return NULL;
}
