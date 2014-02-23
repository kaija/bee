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
    //generate pairing command
    char *tlv = NULL;
    //1. switch command type
    int total = 0;
    unsigned char sw[2];
    sw[0] = 0x00;
    sw[1] = 0x01;
    total = bee_tlv_appender(0, 2, sw, &tlv, total );
    //2. tlv class
    unsigned char cla[2];
    cla[0] = 0x00;
    cla[1] = 0x03;
    total = bee_tlv_appender(1, 2, cla, &tlv, total );
    //3. tlv cmd
    char cmd[]= "pair_start";
    total = bee_tlv_appender(2, strlen(cmd), cmd, &tlv, total );
    //4. tlv value
    char val[]= "{\"id\":\"700000165\"}";
    total = bee_tlv_appender(3, strlen(val), val, &tlv, total );
    //5. tlv pid
    char pid[]= "112233445566";
    total = bee_tlv_appender(4, strlen(pid), pid, &tlv, total );
    //6. tlv nonce
    char nonce[]= "fb0e4ebc6e61e21b82ac0faf3ade9dbd";
    total = bee_tlv_appender(7, strlen(nonce), nonce, &tlv, total );
    //7. wrap a total length TLV
    void *output = NULL;
    total = bee_tlv_creator(0xffff, total, tlv, &output);

    printf("Cloud Aget TLV Length: %d\n Value:\n", total);
    noly_hexdump(output, total);
    printf("Send Command to Cloud Agent\n");
    bee_send_data("f835dd1af5f3", -1 , output, total, SM_MSG_TYPE_RT);
    return 0;
}
int data_callback(void *ctx, char *id, int cid, void *data, int len)
{
    printf("recv from %d length : %d\n", cid, len);
    noly_hexdump(data, len);
    char md[34];
    char str[128];
    memset(md, 0, 34);
    void *data_tlv = NULL;
    unsigned long data_len = 0;
    unsigned long total = 0;
    unsigned long type = 0;
    int ret = bee_tlv_parser(data, &type, &data_tlv, &total);
    if(ret > 0){
        int offset = 0;
        void *val = NULL;
        int offset_sum = 0;
        printf("TLV length %lu\n", total);
        int count = 0;
        while((offset = bee_tlv_parser(data_tlv + offset_sum, &type, &val, &data_len)) != 0){
            count ++;
            offset_sum += offset;
            printf("type %lu\n", type);
            printf("data len %lu offset %lu\n", data_len, offset_sum);
            //noly_hexdump(val, data_len);
            if(type == 3){
                char cha[64];
                memset(cha, 0, 64);
                int s = noly_json_str_get_str((char *)val, "challenge",  cha , 64);
                if(s == -1) return 0;
                printf("challenge:%s\n", cha);
                int halen = sprintf(str,"%s%s%s","700000165", "12345678", cha );
                http_md5sum(str, halen, md);
                break;
            }
        }
#if 1
    printf("%s\n", str);
    printf("%s\n", md);
#endif
    //generate pairing command
    char *tlv = NULL;
    //1. switch command type
    total = 0;
    unsigned char sw[2];
    sw[0] = 0x00;
    sw[1] = 0x01;
    total = bee_tlv_appender(0, 2, sw, &tlv, total );
    //2. tlv class
    unsigned char cla[2];
    cla[0] = 0x00;
    cla[1] = 0x03;
    total = bee_tlv_appender(1, 2, cla, &tlv, total );
    //3. tlv cmd
    char cmd[]= "pair_response";
    total = bee_tlv_appender(2, strlen(cmd), cmd, &tlv, total );
    //4. tlv value
    char tlv_val[128];
    sprintf(tlv_val, "{\"id\":\"700000165\", \"response\":\"%s\"}", md);
printf("JSON response %d\n", tlv_val);
    total = bee_tlv_appender(3, strlen(tlv_val), tlv_val, &tlv, total );
    //5. tlv pid
    char pid[]= "112233445566";
    total = bee_tlv_appender(4, strlen(pid), pid, &tlv, total );
    //6. tlv nonce
    char nonce[]= "fb0e4ebc6e61e21b82ac0faf3ade9dbd";
    total = bee_tlv_appender(7, strlen(nonce), nonce, &tlv, total );
    //7. wrap a total length TLV
    void *output = NULL;
    total = bee_tlv_creator(0xffff, total, tlv, &output);

    printf("Cloud Aget TLV Length: %d\n Value:\n", total);
    noly_hexdump(output, total);
    printf("Send Command to Cloud Agent\n");
    bee_send_data("600000264", -1 , output, total, SM_MSG_TYPE_RT);
    }
}

int main()
{
    bee_user_init(NULL);
    bee_set_service("HA-45058956", "0744424235");
    bee_reg_status_cb(status_cb);
//#ifdef OFFLINE
    bee_set_user_info("kaija.chang@gmail.com", "mamamiya", BEE_GUEST_UID);
    bee_offline();
    bee_reg_status_cb(status_cb);
    bee_reg_sender_cb(connector_callback);
    bee_discover_nbr();
    bee_reg_message_cb(data_callback);
    sleep(3);
    bee_connect("600000264");
    while(1){
        sleep(2);
    }
	return 0;
}
