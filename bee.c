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
    .mqtt.security = 1,
    .local.sock = 0,
};
void *bee_main(void *data);
int bee_init(int type);
int bee_login(int type);
int bee_mqtt_start();
int bee_message_handler(char *src, char *data);
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
    bee.status = BEE_CONNECTED;
    PLOG(PLOG_LEVEL_INFO,"Subscribed (mid: %d): %d", mid, granted_qos[0]);
}

void bee_mqtt_log_callback(struct mosquitto *mosq, void *obj, int level, const char *str)
{
    if(str) PLOG(PLOG_LEVEL_INFO,"%s\n", str);
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
            sm_get_msg(bee.sm.session, bee.sm.api_key, srl);
        }
    }else{
        PLOG(PLOG_LEVEL_DEBUG,"Drop unknown message\n");
    }
}

int bee_mqtt_start()
{
    int rc = 0;
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
    rc = mosquitto_connect(bee.mqtt.mosq, bee.mqtt.server, bee.mqtt.port, bee.mqtt.keepalive);
    if(rc){
        if(rc == MOSQ_ERR_ERRNO){
            PLOG(PLOG_LEVEL_ERROR, "%s\n", strerror(errno));
        }else{
            PLOG(PLOG_LEVEL_ERROR, "Unable to connect (%d)\n",rc);
        }
    }
    return 0;
err:
    mosquitto_lib_cleanup();
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
    return 0;
}
/* ===============================================
 * BEE config function
 */
void bee_get_version(char *ver)
{

}

void bee_get_uid(char *uid)
{

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
    return BEE_API_OK;
}

int bee_del_user()
{
    return BEE_API_OK;
}

struct bee_nbr *bee_get_nbr_list()
{
    return NULL;
}

int bee_discover_nbr()
{
    return BEE_API_OK;
}

int bee_delete_nbr_list()
{
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

int bee_dev_init()
{
    bee_init(SM_TYPE_DEVICE);
    return BEE_API_OK;
}

int bee_init(int type)
{
    list_init(&bee.local.client);
    plogger_set_path("/tmp/p2p.log");
    plogger_enable_file(PLOG_LEVEL_INFO);
    bee.type = type;
    bee.mqtt.will = BEE_FALSE;
    bee.mqtt.qos = 1;
    bee.status = BEE_INIT;
    bee.mqtt.debug = BEE_TRUE;
    bee.mqtt.retain = 0;
    bee.mqtt.keepalive = BEE_KEEPALIVE; // Default 60 sec keepalive
    bee.mqtt.clean_sess = BEE_TRUE;
    if(bee.ssdp.sock == 0){
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
    return BEE_API_OK;
}

int bee_user_login_cert(char *cert_path, char *pkey_path, char *pw)
{
    if(!cert_path || !pkey_path || !pw) return BEE_API_PARAM_ERROR;
    strncpy(bee.sm.certpath, cert_path, HTTP_CA_PATH_LEN);
    strncpy(bee.sm.pkeypath, pkey_path, HTTP_CA_PATH_LEN);
    strncpy(bee.sm.pkeypass, pw, HTTP_PASSWORD_LEN);
    bee_login(SM_TYPE_USER);
    return BEE_API_OK;
}
int bee_dev_login_id_pw(char *id, char *pw)
{
    if(!id || !pw) return BEE_API_PARAM_ERROR;
    strncpy(bee.sm.username, id, HTTP_USERNAME_LEN);
    strncpy(bee.sm.password, pw, HTTP_PASSWORD_LEN);
    bee_login(SM_TYPE_DEVICE);
    return BEE_API_OK;
}

int bee_dev_login_cert(char *cert_path, char *pkey_path, char *pw)
{
    if(!cert_path || !pkey_path || !pw) return BEE_API_PARAM_ERROR;
    strncpy(bee.sm.certpath, cert_path, HTTP_CA_PATH_LEN);
    strncpy(bee.sm.pkeypath, pkey_path, HTTP_CA_PATH_LEN);
    strncpy(bee.sm.pkeypass, pw, HTTP_PASSWORD_LEN);
    bee_login(SM_TYPE_DEVICE);
    return BEE_API_OK;
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
    struct msg_service_info info;
    if(sm_get_msg_info(type, bee.sm.session, &info) == 0){
        strncpy(bee.mqtt.username, info.mqtt_id, HTTP_USERNAME_LEN);
        strncpy(bee.mqtt.password, info.mqtt_pw, HTTP_PASSWORD_LEN);
        strncpy(bee.mqtt.server, info.mqtt_ip, HTTP_IP_LEN);
        bee.mqtt.port = info.mqtt_port;
        //FIXME topic get from cloud?
        sprintf(bee.mqtt.topic, "client/%s/%s-HA", bee.mqtt.username, bee.mqtt.username);
        PLOG(PLOG_LEVEL_INFO, "MQTT info\nIP:%s\nPort:%d\nID:%s\nPW:%s\n", bee.mqtt.server, bee.mqtt.port, bee.mqtt.username, bee.mqtt.password);
    }
    bee.status = BEE_LOGIN;
    return BEE_API_OK;
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
    //FIXME add local tcp socket handle
    return BEE_API_OK;
}
int bee_send_message(char *id, void *data, unsigned long len, int type)
{
    int ret = -1;
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
        noly_hexdump(tlv, 8 + len );
        bee_send_message(id, tlv, len + 8, type);
        free(tlv);
    }
    return BEE_API_OK;
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
        noly_hexdump(tlv, 8 + len );
        bee_send_message(id, tlv, len + 8, SM_MSG_TYPE_RT);
        free(tlv);
    }
    return BEE_API_OK;
}

int bee_message_handler(char *src, char *data)
{
    PLOG(PLOG_LEVEL_DEBUG,"%s\n%s\n", src, data);
    size_t tlv_len;
    char *tlv = base64_decode(data, strlen(data), &tlv_len);
    if(tlv){
        if(tlv[1] == 0x01){//Data
        }else if(tlv[1] == 0x00){//SM
            
        }else{//P2P connection use
            PLOG(PLOG_LEVEL_INFO,"Bee library not support P2P mode reply something\n");
            char reply[] = "{\"cmd\":\"conn_reject\",\"reason\":\"not support\"}";
            bee_send_p2p(src, reply, strlen(reply));
        }
        free(tlv);
    }
    return 0;
}

int bee_reg_sm_cb(int (*callback)(void *data, int len))
{
    return BEE_API_OK;
}

int bee_reg_message_cb(int (*callback)(char *id, void *data, int len))
{
    return BEE_API_OK;
}

void bee_check()
{
    if(bee.status == BEE_LOGIN && bee.mqtt.mosq == NULL)
    {
        if(bee_mqtt_start() == 0){
            bee.status = BEE_CONNECTING;
            bee.mqtt.sock = mosquitto_socket(bee.mqtt.mosq);
        }
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

int bee_local_save_read(int fd)
{
    int len;
    char buf[BEE_PKT_SIZE];
    memset(buf, 0, BEE_PKT_SIZE);
    len = read(fd, buf, BEE_PKT_SIZE-1);
    if(len) printf("%s\n", buf);
    return len;
}

int bee_local_cli_handle(fd_set *fs)
{
    int size = list_size(&bee.local.client);
    int i = 0;
    for(i=0;i<size;i++){
        struct bee_client *client = list_get_at(&bee.local.client, i);
        if(client && FD_ISSET(client->fd, fs)){
            int len = bee_local_save_read(client->fd);
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
        bee_local_save_read(fd);
        //FIXME Add status callback
    }else{
        PLOG(PLOG_LEVEL_ERROR,"accept connection error (%d)%s\n", errno, strerror(errno));
    }
    return 0;
}

void *bee_main(void *data)
{
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
        if(bee.mqtt.sock > 0){
            FD_SET(bee.mqtt.sock, &rfs);
            struct mosquitto *mosq = bee.mqtt.mosq;
            if(mosq->out_packet || mosq->current_out_packet){
                FD_SET(bee.mqtt.sock, &wfs);
            }
            max = MAX(bee.mqtt.sock, max);
        }
        max = MAX(max, bee_local_cli_fd_set(&rfs));// add local client socket
        int ret = select(max+1, &rfs, &wfs, NULL, &tv);
        if(ret == 0){
            PLOG(PLOG_LEVEL_DEBUG, "Periodically check\n");
            bee_check();
        }else if(ret < 0){
            PLOG(PLOG_LEVEL_ERROR, "socket select error\n");
            //FIXME handle mqtt socket error case
            bee_local_cli_handle(&rfs);
            return 0;
        }else{
            if(FD_ISSET(bee.event_sock, &rfs)){
            }
            bee_mqtt_handler(&rfs, &wfs);
            if(FD_ISSET(bee.local.sock, &rfs)){
                PLOG(PLOG_LEVEL_DEBUG, "Local client socket connected %d\n", bee.local.sock);
                bee_local_serv_handle(bee.local.sock); 
            }
            bee_local_cli_handle(&rfs);
            //TODO check socket one by one
        }
    }
    if(bee.event_sock > 0) {
        close(bee.event_sock);
        bee.event_sock = 0;
    }
    if(bee.local.sock > 0) {
        close(bee.local.sock);
        bee.local.sock = 0;
    }
    if(bee.mqtt.mosq) {
        mosquitto_disconnect(bee.mqtt.mosq);
        mosquitto_lib_cleanup();
        mosquitto_destroy(bee.mqtt.mosq);
    }
    PLOG(PLOG_LEVEL_INFO, "Library thread stopped\n");
    return NULL;
}
