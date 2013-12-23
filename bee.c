#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#include "mosquitto.h"

#include "bee.h"
#include "utils.h"
#include "lssdp.h"
#include "log.h"
static struct bee_struct bee = {
    .run = BEE_FALSE,
};
void *bee_main(void *data);
int bee_init(int type);
int bee_login(int type);
int mqtt_start();
/* ===============================================
 *     Mosquitto callback area
 */
void mqtt_connect_callback(struct mosquitto *mosq, void *obj, int result)
{
    if(!result){
        //mosquitto_subscribe(mosq, NULL, info->mqtt_topic, info->mqtt_qos);
    }else{
        fprintf(stderr, "%s\n", mosquitto_connack_string(result));
        PLOG(PLOG_LEVEL_ERROR,"%s", mosquitto_connack_string(result));
    }
}

void mqtt_subscribe_callback(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos)
{
    PLOG(PLOG_LEVEL_INFO,"Subscribed (mid: %d): %d", mid, granted_qos[0]);
}

void mqtt_log_callback(struct mosquitto *mosq, void *obj, int level, const char *str)
{
    if(str) PLOG(PLOG_LEVEL_INFO,"%s\n", str);
}

void mqtt_message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
    PLOG(PLOG_LEVEL_DEBUG, "%s\n", message->payload);
}

int mqtt_start()
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
    mosquitto_log_callback_set(bee.mqtt.mosq, mqtt_log_callback);
    if(bee.mqtt.security){
        if(mosquitto_username_pw_set(bee.mqtt.mosq, bee.mqtt.username, bee.mqtt.password) != 0){
            goto err;
        }
    }
    mosquitto_connect_callback_set(bee.mqtt.mosq, mqtt_connect_callback);
    mosquitto_message_callback_set(bee.mqtt.mosq, mqtt_message_callback);
    mosquitto_subscribe_callback_set(bee.mqtt.mosq, mqtt_subscribe_callback);
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
            return BEE_API_FAIL;
        }
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

int bee_dev_login_cert(char *id, char *pw)
{
    bee_login(SM_TYPE_DEVICE);
    return BEE_API_OK;
}

int bee_login(int type){
    int ret = 0;
    if(type == SM_TYPE_USER){
        ret = sm_login(SM_LOGIN_IDPW, bee.sm.username, bee.sm.password, bee.sm.certpath, bee.sm.pkeypath, bee.sm.session, bee.sm.uid);
    }else{
        ret = sm_dev_login(SM_LOGIN_IDPW, bee.sm.username, bee.sm.password, bee.sm.certpath, bee.sm.pkeypath, bee.sm.session, bee.sm.uid);
    }
    if(ret != 0){
        PLOG(PLOG_LEVEL_WARN, "Login service manager error %d\n", ret);
        return BEE_API_FAIL;
    }
    return BEE_API_OK;
}

int bee_logout()
{
    PLOG(PLOG_LEVEL_INFO, "Logout\n");
    bee.run = BEE_FALSE;
    noly_udp_sender(BEE_LOCALHOST, bee.event_port, "disconn", strlen("disconn"));
    return BEE_API_OK;
}

int bee_destroy()
{
    return BEE_API_OK;
}

int bee_send_message(char *id, int cid, void *data, int len)
{
    return BEE_API_OK;
}

int bee_reg_sm_cb(int (*callback)(void *data, int len))
{
    return BEE_API_OK;
}

int bee_reg_message_cb(int (*callback)(char *id, void *data, int len))
{
    return BEE_API_OK;
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
        int ret = select(max+1, &rfs, &wfs, NULL, &tv);
        if(ret == 0){
            PLOG(PLOG_LEVEL_DEBUG, "Periodically check\n");
        }else if(ret < 0){
            PLOG(PLOG_LEVEL_ERROR, "socket select error\n");
        }else{
            if(FD_ISSET(bee.event_sock, &rfs)){
            }
            //TODO check socket one by one
        }
    }
    if(bee.event_sock > 0) {
        close(bee.event_sock);
        bee.event_sock = 0;
    }
    PLOG(PLOG_LEVEL_INFO, "Library thread stopped\n");
    return NULL;
}
