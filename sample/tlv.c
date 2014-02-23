#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int simple()
{
    char a[] = "a";
    char b[] = "bb";
    char c[] = "cc";
    char *data = NULL;
    int total = 0;
    total = bee_tlv_appender(1, strlen(a), a, &data, total);
    total = bee_tlv_appender(2, strlen(b), b, &data, total);
    total = bee_tlv_appender(3, strlen(c), c, &data, total);
    noly_hexdump(data, total);
    return 0;
}
int cloud_agent_command()
{
    char *tlv = NULL;
    //1. switch command type
    int total = 0;
    unsigned char sw[2];
    sw[0] = 0x00;
    sw[1] = 0x02;
    total = bee_tlv_appender(0, 2, sw, &tlv, total );
    //2. tlv class
    unsigned char cla[2];
    cla[0] = 0x00;
    cla[1] = 0x08;
    total = bee_tlv_appender(1, 2, cla, &tlv, total );
    //3. tlv cmd
    char cmd[]= "set_power";
    total = bee_tlv_appender(2, strlen(cmd), cmd, &tlv, total );
    //4. tlv value
    char val[]= "{\"power\":\"on\"}";
    total = bee_tlv_appender(3, strlen(val), val, &tlv, total );
    //5. tlv pid
    char pid[]= "112233445566";
    total = bee_tlv_appender(3, strlen(pid), pid, &tlv, total );
    //6. tlv nonce
    char nonce[]= "fb0e4ebc6e61e21b82ac0faf3ade9dbd";
    total = bee_tlv_appender(7, strlen(nonce), nonce, &tlv, total );
    //7. wrap a total length TLV
    void *output = NULL;
    total = bee_tlv_creator(0xffff, total, tlv, &output);

    printf("Cloud Aget TLV Length: %d\n Value:\n", total);
    noly_hexdump(output, total);

}
int main()
{
    simple();

    cloud_agent_command();
    return 0;
}
