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
