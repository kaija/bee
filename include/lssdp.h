/**
 * @file    lssdp.h
 * @brief   Lite SSDP Library header
 * @date    2013/07/18
 * @author  Sway Huang <sway.huang1228@gmail.com>
 */
#ifndef __LSSDP_H
#define __LSSDP_H

#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/queue.h>
#include <pthread.h>

enum{
    SSDP_ERR_NOMEM,
    SSDP_ERR_BIND
};

enum{
    METHOD_MSEARCH=1,
    METHOD_NOTIFY,
    METHOD_RESPONSE,
    METHOD_MAX,
};

enum{
    FIELD_ST=1,
    FIELD_NT,
    FIELD_USN,
    FIELD_LOCATION,
    FIELD_MAX,
};

#define SSDP_MULTICAST      "239.255.255.250"
#define SSDP_PORT           1900

#define SSDP_ST_LEN         128
#define SSDP_USN_LEN        128
#define SSDP_LOCATION_LEN   128
#define SSDP_SERVER_LEN     128

#define SSDP_MAX_IFACE      10
#define SSDP_MAC_LEN        128
#define SSDP_IP_LEN         128
#define SSDP_ID_LEN         32
#define SSDP_IFACE_LEN      16

#define SSDP_MAX_PKT_LEN    1024
#define SSDP_REQ_BUF_SIZE   512
#define SSDP_RES_BUF_SIZE   512

#define SSDP_MAX_SERVICE    16

#define SSDP_DEBUG          0

typedef struct lssdp_service_list
{
    char    st[SSDP_ST_LEN];
    char    usn[SSDP_USN_LEN];              //unique service number
    char    sm_id[SSDP_ID_LEN];
    char    location[SSDP_LOCATION_LEN];    //service location
    char    server[SSDP_SERVER_LEN];        //server name
    struct lssdp_service_list   *next;
}lssdp_service_list_t;

typedef struct lssdp_service_info{
    char    st[SSDP_ST_LEN];                //service type
    lssdp_service_list_t *list;
}lssdp_service_info_t;

typedef struct lssdp_my_service_info{
    int  interface;
    char iface[SSDP_MAX_IFACE][SSDP_IFACE_LEN];
    char usn[SSDP_LOCATION_LEN];
    char sm_id[SSDP_ID_LEN];
    char location[SSDP_MAX_IFACE][SSDP_LOCATION_LEN];
    int  port;
    char server[SSDP_SERVER_LEN];
    char st[SSDP_ST_LEN];
}lssdp_my_service_info;


/**
 * @name    lssdp_create_socket
 * @brief   create a SSDP socket
 * @retval  >0 socket fd
 * @retval  <0 failure with error code
 */
int lssdp_create_socket();

/**
 * @name    lssdp_set_service
 * @brief   set my service informationa
 * @param   service type
 * @param   unique serial number
 * @param   location information or ip address
 * @param   server name
 * @retval  0 success
 * @retval  <0 failure with error code
 */
int lssdp_set_service(char *st, char *usn, char *sm_id, int port, char *server);

/**
 * @name    lssdp_request_service
 * @brief   request send a service discover
 * @param   service name
 * @retval  0 success
 * @retval  <0 failure with error code
 */
int lssdp_request_service(char *service);

/**
 * @name    lssdp_list_service
 * @brief   search a service list
 * @param   service name
 * @retval  service list
 * @retval  null service not found
 */
lssdp_service_list_t* lssdp_list_service(char *service);

/**
 * @name    lssdp_delete_list
 * @brief   delete a service list
 * @param   service name
 * @retval  0 success
 */
int lssdp_delete_list(char *service);

/**
 * @name    lssdp_process_packet
 * @brief   process a ssdp packet
 * @param   socket fd
 * @param   source address of the payload
 * @param   payload
 * @param   payload length
 * @retval  0 success
 * @retval  <0 failure with error code
 */
int lssdp_process_packet(int sock, struct sockaddr *addr, void *payload, int len);

/**
 * @name    lssdp_start_daemon
 * @brief   create a thread to handle ssdp packets
 * @retval  0 success
 * @retval  <0 failure with error code
 */
int lssdp_start_daemon();

/**
 * @name    lssdp_get_iface
 * @brief   get network interface
 */
void lssdp_get_iface(char *iface);

/**
 * @name    lssdp_get_self_ip
 * @brief   get the self ip
 * @param   network interface
 * @param   string pointer
 */
void lssdp_get_self_ip(char *iface, char *ip);

/**
 * @name    lssdp_get_self_mac
 * @brief   get the self mac
 * @param   string pointer
 */
void lssdp_get_self_mac(char *iface, char *mac);

/**
 * @name    lssdp_dump_service_list
 * @brief   print out the service list
 */
void lssdp_dump_service_list();

/**
 * @name    add_multicast_membership
 * @brief   add socket multicast membership
 * @param   sock the socket fd
 */
int add_multicast_membership(int sock);
#endif
