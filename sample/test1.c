#include <stdio.h>
#include "bee.h"
int a()
{
    bee_dev_init();
    bee_set_service("HA-45058956", "0744424235");
    while(1){
        if(bee_dev_login_id_pw("f835dd000003", "gemtek") == BEE_API_OK){
            bee_send_p2p("600000125", "asdfghjk", 8);
        }
        sleep(1);   
    }
    sleep(3);
    //bee_send_data("600000125", 0, "qwertyui", 8, 0);
    bee_send_data("600000125", 0, "qwertyui", 8, SM_MSG_TYPE_RT);
    bee_send_p2p("600000125", "asdfghjk", 8);
    sleep(100);
    return 0;
}
int status_cb(int status)
{
    if(status == BEE_CONNECTED){
        bee_send_p2p("600000125", "asdfghjk", 8);
    }
}

int b()
{
    bee_dev_init();
    bee_set_service("HA-45058956", "0744424235");
    bee_reg_status_cb(status_cb);
    if(bee_dev_login_id_pw("f835dd000003", "gemtek") == BEE_API_OK){
    }
    sleep(100);
    return 0;
}

int main()
{
    b();
    return 0;
}
