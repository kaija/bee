#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "bee.h"

int ok = 0;
int status_cb(void *ctx, int status)
{
    if(status == BEE_CONNECTED){
        ok = 1;
    }
    return 0;
}

int b()
{
    bee_user_init(NULL);
    bee_set_service("HA-45058956", "0744424235");
    bee_reg_status_cb(status_cb);
    if(bee_user_login_id_pw("kaija.chang.co@gmail.com", "mamamiya") == BEE_API_OK){
        struct bee_user_list list;
        bee_dev_get_user(&list);
    }
    while(1){
        sleep(5);
        if(ok == 1) bee_connect("600000609");
    }
    return 0;
}

int main()
{
    b();
    return 0;
}
