#include <stdio.h>
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
int thread()
{
    bee_user_init(NULL);
    bee_set_service("HA-45058956", "0744424235");
    bee_reg_status_cb(status_cb);
    bee_user_login_id_pw("kaija.chang@gmail.com", "mamamiya");
    bee_reg_status_cb(status_cb);
    while(1){
        sleep(1);
        if(conn_status == 1){
            conn_status = 2;
            printf("Pause Library\n");
            bee_pause();
        }else if(conn_status == 2){
            printf("Resume Library\n");
            conn_status = 3;
            bee_resume();
        }else if(conn_status == 3){
            return 0;
        }
    }
	return 0;
}

int status_cb2(void *ctx, int status)
{
    if(status == BEE_CONNECTED){
        printf("Pause Library\n");
        bee_pause();
    }
    return 0;
}


int nothread(){
    bee_user_init_v2(NULL);
    bee_set_service("HA-45058956", "0744424235");
    bee_reg_status_cb(status_cb2);
    bee_user_login_id_pw("kaija.chang@gmail.com", "mamamiya");
    //bee_reg_app_cb(app_callback, 3);
    bee_loop_forever();
    printf("bee_loop_forever end resume\n");
    //bee_resume();
    //printf("???\n");
    return 0;
}
int main()
{
    thread();
    bee_destroy();
    nothread();
    bee_destroy();
    conn_status = 0;
    thread();
    return 0;
}
