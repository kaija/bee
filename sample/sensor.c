#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "bee.h"
int status_cb(void *ctx, int status)
{
    if(status == BEE_CONNECTED){
        fprintf(stdout, "********** Connected to Cloud\n");
        //bee_send_conn_req("600000125");
        //unsigned char tmp[]= "test  123456";
        //noly_hexdump(tmp, 12);
        //bee_send_data("600000125", -1, tmp, 12, SM_MSG_TYPE_RT);
        //bee_send_message("600000125", "hello", 5, SM_MSG_TYPE_DEFAULT);
    }
    return 0;
}
int conn_cb(void *ctx, char *remote, int cid, int status)
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
    if(status == BEE_CONN_DISCONN_MANUAL || status == BEE_CONN_DISCONN_TIMEOUT || status == BEE_CONN_DISCONN_SERVER ){
        if(cid > 0){
            fprintf(stdout, "********** Local connection %d disconnected\n", cid);
        }
        if(remote){
            fprintf(stdout, "********** Remote connection %s disconnected\n", remote);
        }
    }
    if(status == BEE_CONN_ACCEPT){
        if(cid > 0){
            fprintf(stdout, "********** Local connection %d connected\n", cid);
        }
        if(remote){
            fprintf(stdout, "********** Remote connection %s connected\n", remote);
        }
    }
    return BEE_CONN_ACCEPT;
}

int cmd_callback(void *ctx, char *id, int cid, void *data, int len)
{
    fprintf(stdout, "         Recv command\n");
    fprintf(stdout, "===============================\n");
    bee_hexdump(data, len);
    fprintf(stdout, "===============================\n");
    fprintf(stdout, "%s\n", (char *)data);
    return 0;
}

int service()
{
    bee_dev_init(NULL);
    bee_set_service("HA-45058956", "0744424235");
    bee_reg_status_cb(status_cb);
    bee_reg_receiver_cb(conn_cb);
    bee_reg_message_cb(cmd_callback);

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
