#include <stdio.h>
#include "bee.h"
int status_cb(int status)
{
    if(status == BEE_CONNECTED){
        fprintf(stdout, "********** Connected to Cloud\n");
        bee_send_conn_req("600000125");
    }
}
int conn_cb(char *remote, int cid, int status)
{
    if(status == BEE_CONN_REQUEST){
        if(cid > 0){
            fprintf(stdout, "********** Local connection %d connect request\n", cid);
        }
        if(remote){
            fprintf(stdout, "********** Remote connection %s connection request\n", remote);
        }
        return BEE_CONN_ACCEPT;
        //return BEE_CONN_REJECT; //reject if you like
    }
    if(status == BEE_CONN_DISCONN){
        if(cid > 0){
            fprintf(stdout, "********** Local connection %d disconnected\n", cid);
        }
        if(remote){
            fprintf(stdout, "********** Remote connection %s disconnected\n", remote);
        }
    }
    return BEE_CONN_ACCEPT;
}

int service()
{
    bee_dev_init();
    bee_set_service("HA-45058956", "0744424235");
    bee_reg_status_cb(status_cb);
    bee_reg_connection_cb(conn_cb);

    if(bee_dev_login_id_pw("f835dd000003", "gemtek") == BEE_API_OK){
        fprintf(stdout, "*********** Login Cloud service manager\n");
    }
    while(1){
        sleep(1);
    }
    return 0;
}


int main()
{
    service();
    return 0;
}
