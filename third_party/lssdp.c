#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include "lssdp.h"
#include "log.h"

lssdp_my_service_info lssdp_my_info;
lssdp_service_info_t lssdp_global[SSDP_MAX_SERVICE];
int service_num = 0;

/* bootid and configid */
unsigned int upnp_bootid = 1;
unsigned int upnp_configid = 1337;
/*
    Local function declare area
*/
int lssdp_set_non_blocking(int fd);
int lssdp_set_reuse_addr(int fd);
int add_multicast_membership(int sock);
int get_ssdp_type(const char *packet, ssize_t plen);
int get_ssdp_field(const char *packet, ssize_t plen, lssdp_service_list_t *entry);
int process_ssdp_service_search(int sock, const struct sockaddr *addr, char *my_service, char *st, int st_len, char *id, char *sm_id, char *server_name);
void send_ssdp_search_response(int sock, const struct sockaddr * sockname, const char * st, const char * usn, const char *sm_id, const char * server, const char * location);
int add_to_ssdp_table(lssdp_service_list_t *list, lssdp_service_list_t *entry);
void *ssdp_thread(void *argv);
int lssdp_is_match(char *ip, char *host);
/*
    function
*/
int lssdp_create_socket()
{
    int sock;
    struct sockaddr_in sockname;
    bzero(&sockname, sizeof(sockname));
    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if(sock > 0){
        sockname.sin_addr.s_addr = htonl(INADDR_ANY);
        sockname.sin_port = htons(SSDP_PORT);
        sockname.sin_family = AF_INET;
        lssdp_set_non_blocking(sock);
        lssdp_set_reuse_addr(sock);
        if(bind(sock, (struct sockaddr *)&sockname, sizeof(sockname)) != 0){
            PLOG(PLOG_LEVEL_ERROR,"blind: err\n");
            close(sock);
            return -1;
        }
    }

    add_multicast_membership(sock);

    return sock;
}

int lssdp_set_service(char *st, char *usn, char *sm_id, int port, char *server)
{
    if(!st || !usn || !server){
        PLOG(PLOG_LEVEL_DEBUG,"lssdp_set_server: parameter null\n");
        return -1;
    }
    if(strlen(st) >= SSDP_ST_LEN || strlen(usn) >= SSDP_USN_LEN || strlen(server) >= SSDP_SERVER_LEN){
        PLOG(PLOG_LEVEL_DEBUG,"lssdp_set_server: over the memery allocated\n");
        return -1;
    }
    lssdp_my_info.port = port;
    strcpy(lssdp_my_info.st, st);
    strcpy(lssdp_my_info.usn, usn);
    strcpy(lssdp_my_info.server, server);
    strcpy(lssdp_my_info.sm_id, sm_id);
    return 0;
}

int lssdp_request_service(char *service)
{
    struct sockaddr_in addr;
    int sock, slen=sizeof(addr);
    char req[SSDP_REQ_BUF_SIZE];

    if ((sock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1){
        PLOG(PLOG_LEVEL_ERROR,"socket() failed\n");
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SSDP_PORT);
    if (inet_aton(SSDP_MULTICAST, &addr.sin_addr)==0) {
        PLOG(PLOG_LEVEL_ERROR,"inet_aton() failed\n");
    }

    snprintf(req, sizeof(req), "M-SEARCH * HTTP/1.1\r\n"
        "HOST:239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "ST:%s\r\n"
        "MX:1\r\n"
        "\r\n",
        service);

    if(sendto(sock, req, strlen(req), 0, (struct sockaddr *)&addr, slen) == -1){
        PLOG(PLOG_LEVEL_ERROR,"sendto() failed\n");
    }
    close(sock);
    return 0;
}

lssdp_service_list_t* lssdp_list_service(char *service)
{
    int i;
    for(i = 0; i < SSDP_MAX_SERVICE; i++){
        if(strcmp(service, lssdp_global[i].st) == 0){
            return lssdp_global[i].list;
        }
    }
    return NULL;
}

int lssdp_delete_list(char *service)
{
    int i;
    lssdp_service_list_t *tmp, *list;
    for(i = 0; i < SSDP_MAX_SERVICE; i++){
        if(strcmp(lssdp_global[i].st, service) == 0){
            list = lssdp_global[i].list;
            while(list){
                tmp = list;
                list = list->next;
                free(tmp);
            }
            lssdp_global[i].list = NULL;
            return 0;
        }
    }
    return 0;
}

int lssdp_process_packet(int sock, struct sockaddr *addr, void *payload, int len)
{
    int ssdp_type;
    if( sock <= 0 || !addr || !payload || len <= 0){
        PLOG(PLOG_LEVEL_DEBUG,"lssdp_process_packet: param error\n");
        return -1;
    }
    ssdp_type = get_ssdp_type(payload, len);
    if(!ssdp_type) return -1;

    lssdp_service_list_t *entry = malloc(sizeof(*entry));
    memset(entry, '\0', sizeof(*entry));
    get_ssdp_field((const char *)payload, len, entry);
    if(!strlen(entry->st)){
        free(entry);
        return -1;
    }

    if(ssdp_type == METHOD_MSEARCH){
        process_ssdp_service_search(sock, addr, lssdp_my_info.st, entry->st, strlen(entry->st), lssdp_my_info.usn, lssdp_my_info.sm_id, lssdp_my_info.server);
        free(entry);
    }else if(ssdp_type == METHOD_NOTIFY){
        if(SSDP_DEBUG) PLOG(PLOG_LEVEL_DEBUG,"lssdp_process_packet: not support this service type\n");
        free(entry);
    }else if(ssdp_type == METHOD_RESPONSE){
        if(!strlen(entry->st) || !strlen(entry->location) || !strlen(entry->usn) || !strlen(entry->server)){
            free(entry);
            return -1;
        }
        lssdp_service_list_t* list;
        list = lssdp_list_service(entry->st);
        entry->next = NULL;
        if(list == NULL){
            int i;
            for( i = 0; i < SSDP_MAX_SERVICE; i++){
                if(lssdp_global[i].list == NULL){
                    strncpy(lssdp_global[i].st, entry->st, SSDP_ST_LEN);
                    lssdp_global[i].list = entry;
                    break;
                }
            }
        }else{
            add_to_ssdp_table(list, entry);
        }
    }else{
        PLOG(PLOG_LEVEL_DEBUG,"lssdp_process_packet: unknow service type\n");
        free(entry);
        return -1;
    }
    return 0;
}

#ifdef LIBPOCKY
void lssdp_process_packet_libevent(evutil_socket_t sock, short event, void  *arg)
{
    unsigned int    addr_len = 0;
    unsigned char   pkt_buf[SSDP_MAX_PKT_LEN];
    memset(pkt_buf, 0, SSDP_MAX_PKT_LEN);
    struct          sockaddr_in sout;
    memset(&sout, 0, sizeof(struct sockaddr_in));
    size_t          plen;
    plen = recvfrom(sock, pkt_buf, SSDP_MAX_PKT_LEN, 0, (struct sockaddr *)&sout, &addr_len);
    if(plen){
        if(SSDP_DEBUG) PLOG(PLOG_LEVEL_DEBUG,"recv buf: %s\n", pkt_buf);
        lssdp_process_packet(sock, (struct sockaddr *)&sout, pkt_buf, plen);
    }
}
#endif

void *ssdp_thread(void *argv)
{
    fd_set fs;
    int fd_max;
    struct sockaddr_in sendername;
    socklen_t sendername_len;
    char pkt[SSDP_MAX_PKT_LEN];
    ssize_t pkt_len;
    int sock = *(int *)argv;
    for(;;)
    {
        int res;
        FD_ZERO(&fs);
        FD_SET(sock, &fs);
        fd_max = sock + 1;
        res = select(fd_max, &fs, 0, 0, 0);
        if(res < 0){
            PLOG(PLOG_LEVEL_ERROR,"ssdp_thread: socket select error\n");
        }else{
            if(FD_ISSET(sock, &fs)){
                memset(pkt, '\0', sizeof(pkt));
                sendername_len = sizeof(struct sockaddr_in);
                pkt_len = recvfrom(sock, pkt, sizeof(pkt), 0, (struct sockaddr *)&sendername, &sendername_len);
                if(SSDP_DEBUG) PLOG(PLOG_LEVEL_DEBUG,"recv packet %s\n", pkt);
                if(pkt_len > 0){
                    lssdp_process_packet(sock, (struct sockaddr *)&sendername, pkt, pkt_len);
                }
            }else{
                PLOG(PLOG_LEVEL_INFO,"ssdp_thread: time out\n");
            }
        }
    }
    pthread_exit("ssdp thread exit\n");
}

int lssdp_start_daemon()
{
    pthread_t ssdp_pt;
    int sock;
    int *sock_tmp;
    sock_tmp = malloc(1);
    sock = lssdp_create_socket();
    if(sock < 0) return -1;

    *sock_tmp = sock;
    PLOG(PLOG_LEVEL_INFO,"create ssdp thread\n");
    if( pthread_create(&ssdp_pt, NULL, ssdp_thread, (void *)sock_tmp) != 0){
        PLOG(PLOG_LEVEL_ERROR,"ssdp thread create failure\n");
    }
    return 0;
}

int get_ssdp_type(const char *packet, ssize_t plen)
{
    int methodlen;
    for(methodlen = 0; methodlen <plen && (isalpha(packet[methodlen]) || packet[methodlen] == '-'); methodlen++);
    if(methodlen == 8 && 0 == memcmp(packet, "M-SEARCH", 8)){
        return METHOD_MSEARCH;
    }else if(methodlen == 6 && 0 == memcmp(packet, "NOTIFY", 6)){
        return METHOD_NOTIFY;
    }else if(0 == memcmp(packet, "HTTP/1.1 200 OK", 15)){
        return METHOD_RESPONSE;
    }
    return 0;
}

void lssdp_get_iface(char *iface)
{
    int fd;
    struct ifconf ifc;
    int i;
    struct ifreq ifr[SSDP_MAX_IFACE];
    int interface;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    ifc.ifc_buf = (char *)ifr;
    ifc.ifc_len = sizeof(ifr);
    if(ioctl(fd, SIOCGIFCONF, &ifc) == -1){
        PLOG(PLOG_LEVEL_ERROR, "ioctl error\n");
        close(fd);
        return;
    }
    interface = ifc.ifc_len/sizeof(ifr[0]);
    PLOG(PLOG_LEVEL_DEBUG, "IF(%d)\tIP\n", interface);
    memset(&lssdp_my_info, '\0', sizeof(lssdp_my_info));
    lssdp_my_info.interface = interface;
    for(i = 0; i < interface; i++){
        char ip[SSDP_IP_LEN] = {'\0'};
        struct sockaddr_in *address = (struct sockaddr_in *)&ifr[i].ifr_addr;
        if(!inet_ntop(AF_INET, &address->sin_addr, ip, sizeof(ip))){
            PLOG(PLOG_LEVEL_ERROR, "inet_ntop\n");
        }
        strcpy(lssdp_my_info.iface[i], ifr[i].ifr_name);
        strcpy(lssdp_my_info.location[i], ip);
        PLOG(PLOG_LEVEL_DEBUG, "%s\t%s\n", ifr[i].ifr_name, ip);
    }
    close(fd);
}

void lssdp_get_self_ip(char *iface, char *ip)
{
    int fd;
    struct ifreq ifr;
    memset(ip, '\0', SSDP_IP_LEN);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);
    if(ioctl(fd, SIOCGIFADDR, &ifr) == -1){
        PLOG(PLOG_LEVEL_ERROR, "ioctl error\n");
        return;
    }
    close(fd);
    strcpy(ip, (char *)inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr));
    PLOG(PLOG_LEVEL_INFO,"%s: ip address:%s\n", iface, ip);
}

void lssdp_get_self_mac(char *iface, char *mac)
{
    int fd;
    struct ifreq ifr;
    memset(mac, '\0', SSDP_MAC_LEN);

    // FIXME: rewrite iOS version using https://github.com/njh/marquette/blob/master/getMacAddress.m
#ifndef __IOS__
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);

    sprintf(mac,"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
         (unsigned char)ifr.ifr_hwaddr.sa_data[0],
         (unsigned char)ifr.ifr_hwaddr.sa_data[1],
         (unsigned char)ifr.ifr_hwaddr.sa_data[2],
         (unsigned char)ifr.ifr_hwaddr.sa_data[3],
         (unsigned char)ifr.ifr_hwaddr.sa_data[4],
         (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
#endif

    if(SSDP_DEBUG) PLOG(PLOG_LEVEL_INFO,"%s: mac address:%s\n", iface, mac);
}

int get_ssdp_field(const char *packet, ssize_t plen, lssdp_service_list_t *entry)
{
    const char *linestart;
    const char *lineend;
    const char *nameend;
    const char *valuestart;
    int len = 0;

    linestart = packet;
    while(linestart < packet + plen - 2){
        /* start parsing the line : detect line end */
        lineend = linestart;
        while(lineend < packet + plen && *lineend != '\n' && *lineend != '\r'){
            lineend++;
        }
        /* detect name end : ':' character */
        nameend = linestart;
        while(nameend < lineend && *nameend != ':'){
            nameend++;
        }
        /* detect value */
        if(nameend < lineend){
            valuestart = nameend + 1;
        }else{
            valuestart = nameend;
        }
        /* trim spaces */
        while(valuestart < lineend && isspace(*valuestart)){
            valuestart++;
        }
        /* suppress leading " if needed */
        if(valuestart < lineend && *valuestart=='\"'){
            valuestart++;
        }
        if(nameend > linestart && valuestart < lineend){
            int l = nameend - linestart;    /* header name length */
            int m = lineend - valuestart;   /* header value length */
            /* suppress tailing spaces */
            while(m>0 && isspace(valuestart[m-1])){
                m--;
            }
            /* suppress tailing ' if needed */
            if(m>0 && valuestart[m-1] == '\"'){
                m--;
            }
            if(l==2 && 0==strncasecmp(linestart, "st", 2)){
                //st = valuestart;
                //st_len = m;
                len = m;
                strncpy(entry->st, (char *)valuestart, len);
            }else if(l==2 && 0==strncasecmp(linestart, "nt", 2)){
                len = m;
                strncpy(entry->st, (char *)valuestart, len);
            }else if(l==8 && 0==strncasecmp(linestart, "location", 8)){
                len = m;
                strncpy(entry->location, (char *)valuestart, len);
            }else if(l==3 && 0==strncasecmp(linestart, "usn", 3)){
                len = m;
                strncpy(entry->usn, (char *)valuestart, len);
            }else if(l==6 && 0==strncasecmp(linestart, "server", 6)){
                len = m;
                strncpy(entry->server, (char *)valuestart, len);
            }else if(l==5 && 0==strncasecmp(linestart, "sm_id", 5)){
                len = m;
                strncpy(entry->sm_id, (char *)valuestart, len);
            }
        }
        linestart = lineend;
        while((*linestart == '\n' || *linestart == '\r') && linestart < packet + plen){
            linestart++;
        }
    }
    return 0;
}

int process_ssdp_service_search(int sock, const struct sockaddr *addr, char *my_service, char *st, int st_len, char *id, char *sm_id, char *server_name)
{
    int i;
    if(!my_service || !id || !st || st_len==0) return -1;
    PLOG(PLOG_LEVEL_DEBUG,"SSDP M-SEARCH from %s:%d ST: %.*s\n", inet_ntoa(((const struct sockaddr_in *)addr)->sin_addr), ntohs(((const struct sockaddr_in *)addr)->sin_port), st_len, st);
    if(st_len > 0 && (0==memcmp(st, my_service, st_len))){
        for( i = 0; i < lssdp_my_info.interface; i++){
            if(lssdp_is_match(inet_ntoa(((const struct sockaddr_in *)addr)->sin_addr), lssdp_my_info.location[i])){
                send_ssdp_search_response(sock, addr, st, id, sm_id, server_name, lssdp_my_info.location[i]);
            }
        }
    }else{
        PLOG(PLOG_LEVEL_DEBUG,"not match my service my_service %s id %s st %s\n", my_service, id, st);
        return -1;
    }
    return 0;
}

void send_ssdp_search_response(int sock, const struct sockaddr * sockname, const char * st, const char * usn, const char *sm_id, const char * server, const char * location)
{
    int l, n;
    char buf[SSDP_RES_BUF_SIZE];
    socklen_t sockname_len;
    /*
     * follow guideline from document "UPnP Device Architecture 1.0"
     * uppercase is recommended.
     * DATE: is recommended
     * SERVER: OS/ver UPnP/1.0 miniupnpd/1.0
     * - check what to put in the 'Cache-Control' header
     *
     * have a look at the document "UPnP Device Architecture v1.1 */
    l = snprintf(buf, sizeof(buf), "HTTP/1.1 200 OK\r\n"
        "CACHE-CONTROL: max-age=120\r\n"
        /*"DATE: ...\r\n"*/
        "ST: %s\r\n"
        "USN: %s\r\n"
        "SM_ID: %s\r\n"
        "EXT:\r\n"
        "SERVER: %s\r\n"
        "LOCATION: %s:%d\r\n"
        "OPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n" /* UDA v1.1 */
        "01-NLS: %u\r\n" /* same as BOOTID. UDA v1.1 */
        "BOOTID.UPNP.ORG: %u\r\n" /* UDA v1.1 */
        "CONFIGID.UPNP.ORG: %u\r\n" /* UDA v1.1 */
        "\r\n",
        st, usn, sm_id,
        server, location, lssdp_my_info.port,
        upnp_bootid, upnp_bootid, upnp_configid);

    ((struct sockaddr_in *)sockname)->sin_port = htons(SSDP_PORT);
    sockname_len = sizeof(struct sockaddr_in);
    n = sendto(sock, buf, l, 0, sockname, sockname_len );
    if(n < 0){
        PLOG(PLOG_LEVEL_ERROR,"send ssdp response error\n");
    }
}

int add_to_ssdp_table(lssdp_service_list_t *list, lssdp_service_list_t *entry)
{
    if(!list || !entry) return -1;
    lssdp_service_list_t *tmp;
    tmp = list;
    while(tmp != NULL){
        if(!strcmp(tmp->usn, entry->usn)){
            if(!strcmp(tmp->location, entry->location)){
                free(entry);
                return -1;
            }else{
                strcpy(tmp->location, entry->location);
                free(entry);
                return 0;
            }
        }
        if(tmp->next == NULL) break;
        tmp = tmp->next;
    }
    tmp->next = entry;
    return 0;
}

int lssdp_set_non_blocking(int fd)
{
    unsigned long on = 1;
    return ioctl(fd, FIONBIO, &on);
}

int lssdp_set_reuse_addr(int fd)
{
    int on = 1;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *) &on, sizeof(on));
}

int add_multicast_membership(int sock)
{
    if(sock <= 0) return -1;
    struct ip_mreq imr;
    imr.imr_multiaddr.s_addr = inet_addr(SSDP_MULTICAST);
    //imr.imr_interface.s_addr = getifaddr(ifaddr);
    imr.imr_interface.s_addr = htonl(INADDR_ANY);
    if(imr.imr_interface.s_addr == INADDR_NONE){
        PLOG(PLOG_LEVEL_WARN,"no addr or interdace\n");
        return -1;
    }
    if(setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *)&imr, sizeof(struct ip_mreq)) < 0){
        PLOG(PLOG_LEVEL_ERROR,"setsockopt, IP_ADD_MEMBERSHIP: err\n");
        return -1;
    }
    return 0;
}

void lssdp_dump_service_list()
{
    int i;
    lssdp_service_list_t *tmp;
    for(i = 0; i < SSDP_MAX_SERVICE; i++){
        tmp = lssdp_global[i].list;
        if(tmp){
            PLOG(PLOG_LEVEL_DEBUG,"service name is %s\n", lssdp_global[i].st);
            PLOG(PLOG_LEVEL_DEBUG,"ip\t\tid\t\tsm_id\n");
            while(tmp){
                PLOG(PLOG_LEVEL_DEBUG,"%s\t%s\t%s\n", tmp->location, tmp->usn, tmp->sm_id);
                tmp = tmp->next;
            }
            PLOG(PLOG_LEVEL_DEBUG,"--------------------------------------------------\n");
        }
    }
}

int lssdp_is_match(char *src1, char *src2)
{
    in_addr_t ip = inet_addr(src1);
    in_addr_t host = inet_addr(src2);
    ip = ntohl(ip);
    host = ntohl(host);
    uint32_t mask=0xffffff00;
    return ((ip&mask) == (host&mask));
}
