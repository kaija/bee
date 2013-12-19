#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "bee.h"

int bee_log_level(int level)
{
    return BEE_API_OK;
}

int bee_log_to_file(int level, char *path)
{
    return BEE_API_OK;
}

int bee_add_user(char *user, char *dev_info, char *user_key)
{
    return BEE_API_OK;
}

int bee_del_user()
{
    return BEE_API_OK;
}

void bee_get_version(char *ver)
{

}

void bee_get_uid(char *uid)
{

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

int bee_user_init()
{
    return BEE_API_OK;
}

int bee_dev_init()
{
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

int bee_send_data(char *id, int cid, void *data, int len)
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
    return;
}
