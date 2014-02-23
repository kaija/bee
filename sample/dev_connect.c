#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "bee.h"
int status_cb(void *ctx, int status)
{
    if(status == BEE_CONNECTED){
        printf("connect/subscribe to server\n");
    }
    return 0;
}

int b()
{
    bee_dev_init(NULL);
    bee_set_service("HA-45058956", "0744424235");
    bee_reg_status_cb(status_cb);
    
    if(bee_dev_login_id_pw("f835dd000003", "gemtek") == BEE_API_OK){
        struct bee_user_list list;
        bee_dev_get_user(&list);
    }
    while(1){
        sleep(1);
    }
    return 0;
}

int main()
{
    b();
    return 0;
}
