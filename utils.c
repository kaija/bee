#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

#include "parson.h"

int noly_socket_set_reuseaddr(int sk)
{
    int on = 1;
    return setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, (const char *) &on, sizeof(on));
}

int noly_socket_set_nonblock(int sk)
{
    unsigned long on = 1;
    return ioctl(sk, FIONBIO, &on);
}

int noly_udp_rand_socket(int *port)
{
    int sock;
    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(struct sockaddr_in));
    unsigned sin_len = sizeof(struct sockaddr_in);
    serv.sin_addr.s_addr = htonl(INADDR_ANY);
    serv.sin_port = htons(0);
    serv.sin_family = PF_INET;
    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(bind(sock, (struct sockaddr *) &serv, sin_len)<0){
		fprintf(stderr, "bind socket port error\n");
    }
    if(getsockname(sock, (struct sockaddr *)&serv, &sin_len) < 0){
		fprintf(stderr, "get socket name error\n");
    }
    int sport = htons(serv.sin_port);
	fprintf(stdout, "create udp random port %d\n", sport);
    *port = sport;
    return sock;
}

int noly_udp_socket(int port)
{
    int sock;
    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(struct sockaddr_in));
    unsigned sin_len = sizeof(struct sockaddr_in);
    serv.sin_addr.s_addr = htonl(INADDR_ANY);
    serv.sin_port = htons(port);
    serv.sin_family = PF_INET;
    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(bind(sock, (struct sockaddr *) &serv, sin_len)<0){
		fprintf(stderr, "bind socket port error\n");
    }
    if(getsockname(sock, (struct sockaddr *)&serv, &sin_len) < 0){
		fprintf(stderr, "get socket name error\n");
    }
	fprintf(stdout, "create udp random port %d\n", port);
    return sock;
}

int noly_udp_sender(char *addr, int port, char *payload, int len)
{
    int sock;
    struct sockaddr_in serv_addr;
    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sock < 0) { return -1; }
    if(payload == NULL) { return -1; }
    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = PF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(addr);
    serv_addr.sin_port = htons(port);
    ssize_t n = sendto(sock, payload, len, 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    close(sock);
    return n;
}

int noly_tcp_socket(int port, int max_cli)
{
    int max;
    if(port < 1 || port > 65535) return -1;
    if(max_cli < 1 || max_cli > 65535)
        max = 10;
    else
        max = max_cli;
    int sock = -1;
    struct sockaddr_in srv_addr;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock > 0){
        memset(&srv_addr, 0, sizeof(srv_addr));
        srv_addr.sin_family = AF_INET;
        srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        srv_addr.sin_port = htons(port);
        noly_socket_set_reuseaddr(sock);
        noly_socket_set_nonblock(sock);
        if(bind(sock, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0 || listen(sock, max) != 0){
            printf("bind error (%d) %s\n", errno, strerror(errno));
            close(sock);
            sock = -1;
        }
        printf("tcp socket %d port %d have being created\n", sock, port);
    }
    return sock;
}


int json_obj_get_obj(JSON_Object *obj, char *key, char *val, int len)
{
    if(!obj) return -1;
    size_t obj_count = json_object_get_count(obj);
    int i = 0;
    int ret = -1;
    for(i = 0 ; i < obj_count ; i++) {
        const char *name = json_object_get_name(obj, i);
        if(name){
            JSON_Object *sub_obj = json_object_get_object(obj, name);
            if(sub_obj){//recursive
                ret = json_obj_get_obj(sub_obj, key, val, len);
                if(ret == 0) break;
            }else{
                if(strcmp(key, name) == 0){
                    const char *str = json_object_get_string(obj, name);
                    if(!str){
                        double num = json_object_get_number(obj, name);
                        snprintf(val, len ,"%0.0lf\n", num);
                    }else{
                        snprintf(val, len ,"%s", str);
                    }
                    return 0;
                }
            }
        }else{
            printf("json object no name???\n");
        }
    }
    return ret;
}

int json_str_get_obj(char *str, char *key, char *val, int len)
{
    int ret = -1;
    if(!key || !val) return -1;
    JSON_Value *js_val = NULL;
    JSON_Object *js_obj;
    js_val = json_parse_string(str);
    if(json_value_get_type(js_val) == JSONObject){
        js_obj = json_value_get_object(js_val);
        ret = json_obj_get_obj(js_obj, key, val, len);
    }
    json_value_free(js_val);
    return ret;
}

void test()
{
    char val[128];
    char tmp[] = "{\"serial\":450024072,\"src\":\"700000165\",\"type\":5,\"version\":\"1.0\"}";
    json_str_get_obj(tmp, "serial", val, 128);
    printf("result : %s\n", val);
}
