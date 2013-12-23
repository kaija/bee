#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include "mosquitto.h"
#include "bee.h"
#include "log.h"
static struct bee_struct bee;
void *bee_main(void *data);
int bee_init(int type);
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
    if(pthread_create(&bee.bee_thread, NULL, bee_main, (void *)&bee) != 0){
        PLOG(PLOG_LEVEL_FATAL, "Main thread create failure\n");
    }
    PLOG(PLOG_LEVEL_INFO, "Main thread started.\n");
    return BEE_API_OK;
}

int bee_user_login_id_pw(char *id, char *pw)
{
    return BEE_API_OK;
}

int bee_user_login_cert(char *cert_path, char *pkey_path, char *pw)
{
    return BEE_API_OK;
}

int bee_dev_login_id_pw(char *id, char *pw)
{
    return BEE_API_OK;
}

int bee_dev_login_cert(char *id, char *pw)
{
    return BEE_API_OK;
}

int bee_logout()
{
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
    bee.run = 1;
    while(bee.run)
    {
        printf("Check\n");
        sleep(1);
    }
    return NULL;
}
