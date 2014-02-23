#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "bee.h"
#include "parson.h"

static int switch_status = 0;

int set_switch_status(void *ctx, int status)
{
    switch_status = status;
    char cmd[128];
    memset(cmd, 0, 128);
    sprintf(cmd, "led %s 7&", switch_status?"on":"off");
    //system(cmd);
    return 0;
}

void toggle_switch()
{
    switch_status = !switch_status;
    char cmd[128];
    memset(cmd, 0, 128);
    sprintf(cmd, "led %s 7&", switch_status?"on":"off");
    //system(cmd);
}

int status_cb(void *ctx, int status)
{
    if(status == BEE_CONNECTED){
        fprintf(stdout, "********** Connected to Cloud\n");
        system("led on 2 &");
    }else{
        system("led off 2 &");
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
    fprintf(stdout, "Total %d bytes\n", len);
    return 0;
}

int service()
{
    bee_dev_init(NULL);
    bee_set_service("HA-45058956", "0744424235");
    bee_reg_status_cb(status_cb);
    bee_reg_receiver_cb(conn_cb);
    bee_reg_message_cb(cmd_callback);
//#ifdef OFFLINE
#if 0
    bee_set_user_info("f835dd000022","gemtek2014", "600000751");
    bee_ssdp_update();
#else
    bee_set_user_info("f835dd000022","gemtek2014", "600000751");
    if(bee_dev_login_id_pw("f835dd000022", "gemtek2014") == BEE_API_OK){
        fprintf(stdout, "*********** Login Cloud service manager\n");
    }
#endif
    while(1){
        sleep(5);
        toggle_switch();
    }
    return 0;
}

int main()
{
    printf("BEE library version : %s\n", bee_get_version());
    //return 0;
    unsigned char tmp[8];
    tmp[0] = 0x01;
    tmp[1] = 0xff;
    tmp[2] = 0x00;
    tmp[3] = 0x00;
    tmp[4] = 0x00;
    tmp[5] = 0x02;
    tmp[6] = 0x04;
    tmp[7] = 0x04;
    unsigned char *data;
    unsigned long data_len;
    unsigned long type;
    void *kk;
    int ret = bee_tlv_creator(12, 8, &tmp, &kk);
    if(ret > 0){
        bee_tlv_parser(kk, &type, &data, &data_len);
    }
    printf("type: %ld length:%ld value\n", type , data_len);
    noly_hexdump(data, data_len);
    service();
    return 0;
}
