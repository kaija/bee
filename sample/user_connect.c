#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "bee.h"
static int conn_status = 0;
int status_cb(void *ctx, int status)
{
    if(status == BEE_CONNECTED){
        printf("connect/subscribe to server\n");
        conn_status = 1;
    }
    return 0;
}
void get_ver(char *src, struct bee_version *ver)
{
    if(ver && src)
    {
        printf("Remote %s\n", src);
        printf("Library version: %s\n", ver->version);
        printf("sm: %d\n", ver->sm);
        printf("p2p: %d\n", ver->p2p);
        printf("msg: %d\n", ver->msg);
    }
}
int connector_callback(void *ctx, char *remote, int cid, int status){
    printf("%s  %d   connect success\n", remote, cid);
    char *tmp = malloc(64000);
    memset(tmp, 'a', 64000);
    tmp[63999] = 0;
    if(tmp){
        //bee_lib_get_version("600000751", get_ver);
        bee_send_data("600000751", -1 , tmp, 64000, SM_MSG_TYPE_RT);
        bee_send_data("600000751", -1 , tmp, 1280, SM_MSG_TYPE_RT);
    }
    return 0;
}
int main()
{
    bee_user_init(NULL);
    bee_set_service("HA-45058956", "0744424235");
    bee_reg_status_cb(status_cb);
    bee_user_login_id_pw("kaija.chang@gmail.com", "mamamiya");
    bee_reg_status_cb(status_cb);
    bee_reg_sender_cb(connector_callback);
    while(1){
        sleep(1);
        if(conn_status == 1){
            conn_status = 2;
            printf("Connect\n");
            bee_connect("600000751");
        }else if(conn_status == 2){
            printf("Disconnect\n");
            conn_status = 0;
            bee_disconnect("600000749", 0);
        }
    }
	return 0;
}
