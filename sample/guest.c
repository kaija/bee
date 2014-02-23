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
int connector_callback(void *ctx, char *remote, int cid, int status){
    printf("%d   connect success\n", cid);
    char *tmp = malloc(64000);
    memset(tmp, 'a', 64000);
    tmp[63999] = 0;
    if(tmp){
        bee_send_data("f835dd1af5f3", -1 , tmp, 64000, SM_MSG_TYPE_RT);
    }
    return 0;
}

int main()
{
    bee_user_init(NULL);
    bee_set_service("HA-45058956", "0744424235");
    bee_reg_status_cb(status_cb);
    bee_guest_mode("kaija.chang@gmail.com", "12345678");
    //bee_guest_mode("kaija.chang@gmail.com", BEE_GUEST_UID);
    bee_offline();
    bee_discover_nbr();
    bee_reg_status_cb(status_cb);
    bee_reg_sender_cb(connector_callback);
    sleep(2);
    printf("Connect to 600000751......\n");
    bee_connect("f835dd1af5f3");
    while(1){
        sleep(2);
    }
	return 0;
}
