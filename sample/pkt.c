#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


int main()
{
    void *data = malloc(4);
    char *tmp = data;
    tmp[0] = 0x01;
    tmp[1] = 0x02;
    tmp[2] = 0x03;
    tmp[3] = 0x04;
    uint16_t csum = bee_pkt_csum(data, 4);
    unsigned char sum[2];
    sum[0] = csum >> 8;
    sum[1] = csum & 0xFF;
    printf("%02X %02X\n",sum[0], sum[1]);
    return 0;
}
