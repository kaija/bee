#include <stdio.h>
#include <unistd.h>
#include "bee.h"
static int conn_status = 0;
int status_cb(void *ctx, int status)
{
    if(status == BEE_CONNECTED){
        printf("connect/subscribe to server\n");
        conn_status = 1;
        bee_send_data("700000133", -1 , "Hello Sam", strlen("Hello Sam"), SM_MSG_TYPE_RT);
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
    while(1){
        sleep(10);
        if(conn_status == 1){
            conn_status = 2;
            printf("Connect\n");
            bee_connect("600000749");
        }else if(conn_status == 2){
            printf("Disconnect\n");
            conn_status = 0;
            bee_disconnect("600000749", 0);
        }
    }
	return 0;
}
