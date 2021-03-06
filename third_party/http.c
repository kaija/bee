#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <openssl/md5.h>

#include <netinet/tcp.h>

#include "log.h"
#include "http.h"

struct http_data *http_create() {
    int i = 0;
    struct http_data *hd = malloc(sizeof(struct http_data));
    memset(hd, 0, sizeof(struct http_data));
    hd->http.body.start = NULL;
    hd->http.body.size = 0;
    hd->http.body.offset = 0;
    hd->http.buf_offset = 0;
    hd->body_send_len = 0;
    hd->body_send = NULL;
    for(i = 0; i < HTTP_HEADER_NUM ; i++) {
        hd->http.header[i] = NULL;
    }
    hd->tv.tv_sec = HTTP_TIMEOUT;
    return hd;
}

int http_socket_reuseaddr(int sk)
{
	int on = 1;
    return setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, (const char *) &on, sizeof(on));
}

void http_socket_sendtimeout(int sk, int timeout)
{
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    if(setsockopt(sk, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv))!=0){
        PLOG(PLOG_LEVEL_DEBUG, "setsockopt SO_SNDTIMEO failure %s\n", strerror(errno));
    }
}

void http_socket_recvtimeout(int sk, int timeout)
{
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    if(setsockopt(sk, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv))!=0){
        PLOG(PLOG_LEVEL_DEBUG, "setsockopt SO_RCVTIMEO failure %s\n", strerror(errno));
    }
}

static void http_set_tcp_nodelay(int fd)
{
    int enable = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void*)&enable, sizeof(enable));
}

static void http_nonblock_socket(int sk)
{
    unsigned long fc = 1;
    ioctl(sk, FIONBIO, &fc);
}

static void http_block_socket(int sk)
{
    unsigned long fc = 0;
    ioctl(sk, FIONBIO, &fc);
}

int http_set_uri(struct http_data *hd, char *uri) {
    if(hd){
        strncpy(hd->uri.server, uri, HTTP_PATH_LEN);
        return 0;
    }
    return -1;
}

int http_set_cert_path(struct http_data *hd, char *cert, int verify_serv)
{
    if(cert){
        strncpy(hd->cert_path, cert, FILE_PATH_LEN);
        hd->cert_auth = verify_serv;
    }
    return -1;
}

int http_set_key_path(struct http_data *hd, char *key, char *pw)
{
    if(key){
        strncpy(hd->key_path, key, FILE_PATH_LEN);
        if(pw){
            strncpy(hd->passwd, pw,SSL_KEY_PW_LEN);
        }
        return 0;
    }
    return -1;
}

char *http_skip_break(char *ptr)
{
    while(*ptr == '\r' || *ptr == '\n') ptr ++;
    return ptr;
}

char *http_skip_blank(char *ptr)
{
    while(*ptr == ' ') ptr ++;

    return ptr;
}

int http_find_header(struct http_data *hd, char *title, char *out) {
    int count = 0;
    char *header = NULL;
    char *ptr = NULL;
    if(title == NULL || out == NULL) return -1;
    for(count = 0; count < hd->http.header_count; count ++){
        header = hd->http.header[count];
        if(strncasecmp(header, title, strlen(title)) == 0){
            if((ptr = strchr(header, ':')) != NULL) {
                ptr ++;
                ptr = http_skip_blank(ptr);
                strcpy(out, ptr);
            }
            return 0;
        }
    }
    return -1;
}

int http_send(struct http_data *hd, void *buf, int len, int timeout) {
    int retry = 0;
    int ret = -1, sent = 0;
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    if(hd->sk > 0){
        do{
            fd_set fset;
            FD_ZERO(&fset);
            FD_SET(hd->sk , &fset);
            ret = select(hd->sk + 1, NULL, &fset, NULL, &tv);
            if(ret > 0){
                ret = send(hd->sk, (char *)buf + sent, len - sent, 0);
                if(len > 0){
                    if(errno == EAGAIN){
                        retry ++;
                        if(retry == 3){
                            ret = -1;
                            PLOG(PLOG_LEVEL_DEBUG,"Error: send data retry timeout %s\n", strerror(errno));
                            break;
                        }
                    }
                    sent += ret;
                }else{
                    PLOG(PLOG_LEVEL_DEBUG,"Error: send data failure %s\n", strerror(errno));
                    ret = -1;
                    break;
                }
            }
        }while(len > 0 && sent < len);
    }
    if(ret >= 0 )
        return sent;
    else
        return ret;
}

int http_recv(struct http_data *hd, void *buf, int len, int timeout) {
    int ret = -1;
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    if(hd->sk > 0) {
        fd_set fset;
        FD_ZERO(&fset);
        FD_SET(hd->sk , &fset);
        ret = select(hd->sk + 1, &fset, NULL, NULL, &tv);
        if(ret >= 0){
            ret = recv(hd->sk, buf, len, 0);
            if(ret < 0) {
                PLOG(PLOG_LEVEL_DEBUG,"Error: receive data failure %s\n", strerror(errno));
            }
        }else{
            PLOG(PLOG_LEVEL_DEBUG,"Error: select socket failure %s\n", strerror(errno));
        }
    }
    return ret;
}

int https_send(struct http_data *hd, void *buf, int len, int timeout) {
    int ret = -1, sent = 0;
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    if(hd->sk > 0){
        do{
            fd_set fset;
            FD_ZERO(&fset);
            FD_SET(hd->sk , &fset);
            ret = select(hd->sk + 1, NULL, &fset, NULL, &tv);
            ret = SSL_write(hd->ssl, (char *)buf + sent, len - sent);
            if(ret > 0){
                sent += ret;
            }else{
                //FIXME add error handle break do while
                if(errno != -EAGAIN){
                    PLOG(PLOG_LEVEL_WARN,"Send data failure %s\n", strerror(errno));
                    ret = - HTTP_ERR_SEND;
                }else{
                    PLOG(PLOG_LEVEL_ERROR,"Send data failure %s\n", strerror(errno));
                    ret = - HTTP_ERR_SEND;
                    break;
                }
            }
        }while(len > 0 && sent < len);
    }
    if(ret >= 0 )
        return sent;
    else
        return ret;
}

int https_recv(struct http_data *hd, void *buf, int len, int timeout) {
    int ret = -1;
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    if(SSL_pending(hd->ssl) > 0) {
        ret = SSL_read(hd->ssl, buf, len);
        if(ret <= 0) {
            PLOG(PLOG_LEVEL_DEBUG,"Error: receive ssl data failure %s\n", strerror(errno));
            ret = -HTTP_ERR_RECV;
        }
    }else{
        fd_set fset;
        FD_ZERO(&fset);
        FD_SET(hd->sk , &fset);
        ret = select(hd->sk + 1, &fset, NULL, NULL, &tv);
        if(ret > 0){
            ret = SSL_read(hd->ssl, buf, len);
            if(ret <= 0) {
                PLOG(PLOG_LEVEL_DEBUG,"Error: receive data failure %s\n", strerror(errno));
                ret = -HTTP_ERR_RECV;
            }
        }else if(ret == 0){
            PLOG(PLOG_LEVEL_DEBUG,"https recv select timeout\n");
            ret = -HTTP_ERR_TIMEOUT;
        }else{
            if(errno != 0) {
                PLOG(PLOG_LEVEL_DEBUG,"Error: select socket failure %d %s\n", errno, strerror(errno));
                ret = -HTTP_ERR_RECV;
            }else{
                PLOG(PLOG_LEVEL_DEBUG,"https recv select break\n");
                ret = -HTTP_ERR_RECV;
            }
        }
    }
    return ret;
}

int http_host_parse(struct http_data *hd) {
    char *ppath, *pport;
    char *host = NULL;
    char *serv = NULL;
    serv = hd->uri.server;
    if(hd){
        if(strncasecmp(hd->uri.server, "https://", 8) == 0){
            hd->uri.proto = PROTO_HTTPS;
            host = serv + strlen("https://");;
            hd->send = https_send;
            hd->recv = https_recv;
        }else if(strncasecmp(hd->uri.server, "http://", 7) == 0){
            hd->uri.proto = PROTO_HTTP;
            host = serv + strlen("http://");;
            hd->send = http_send;
            hd->recv = http_recv;
        }else{
            PLOG(PLOG_LEVEL_DEBUG,"protocol not support!\n");
            hd->uri.proto = PROTO_HTTP; // Default protocol http
        }
        if((ppath = strchr(host, '/')) != NULL) {
            snprintf(hd->uri.path, HTTP_PATH_LEN, "%s", ppath);
            *ppath = '\0';
        }else{
            snprintf(hd->uri.path, HTTP_PATH_LEN, "*");
        }
        if((pport = strchr(host, ':'))!=NULL) {
            if(*(pport+1) != '\0'){
                hd->uri.port = atoi(pport + 1);
                *pport = '\0';
                snprintf(hd->uri.host, HTTP_HOST_LEN, "%s", host);
            }else{
                *pport = '\0';
                goto no_port;
            }
        }else{
no_port:
            snprintf(hd->uri.host, HTTP_HOST_LEN, "%s", host);
            if(hd->uri.port == 0){
                if(hd->uri.proto == PROTO_HTTPS)
                    hd->uri.port = DEFAULT_HTTPS_PORT;
                else
                    hd->uri.port = DEFAULT_HTTP_PORT;
            }
        }
        if(hd->uri.port > 65535) {
            PLOG(PLOG_LEVEL_DEBUG,"Error: http port out of range!\n");
            if(hd->uri.proto == PROTO_HTTPS)
                hd->uri.port = DEFAULT_HTTPS_PORT;
            else
                hd->uri.port = DEFAULT_HTTP_PORT;
        }
    }else{
        goto err;
    }
    return 0;
err:
    return -HTTP_ERR_PARAM;
}

static int ca_verify_cb(int ok, X509_STORE_CTX *store)
{
    int depth, err;
    X509 *cert = NULL;
    char data[SSL_DATA_LEN];
    if(!ok) {
        cert = X509_STORE_CTX_get_current_cert(store);
        depth = X509_STORE_CTX_get_error_depth(store);
        err = X509_STORE_CTX_get_error(store);
        PLOG(PLOG_LEVEL_DEBUG,"Error with certificate at depth: %i", depth);
        X509_NAME_oneline(X509_get_issuer_name(cert), data, SSL_DATA_LEN);
        PLOG(PLOG_LEVEL_DEBUG," issuer = %s", data);
        X509_NAME_oneline(X509_get_subject_name(cert), data, SSL_DATA_LEN);
        PLOG(PLOG_LEVEL_DEBUG," subject = %s", data);
        PLOG(PLOG_LEVEL_DEBUG," err %i:%s", err, X509_verify_cert_error_string(err));
        return 0;
    }
    return ok;
}

int http_ssl_setup(struct http_data *hd) {
        SSL_load_error_strings();
        if(SSL_library_init() != 1) {
            PLOG(PLOG_LEVEL_DEBUG,"Error: SSL lib init failure\n");
            return -HTTP_ERR_SSL;
        }
        if((hd->ctx = SSL_CTX_new(SSLv3_method())) == NULL) {
            PLOG(PLOG_LEVEL_DEBUG,"Create SSLv3 failure\n");
            if((hd->ctx = SSL_CTX_new(TLSv1_method())) == NULL) {
                PLOG(PLOG_LEVEL_DEBUG,"Create TLSv1 failure\n");
                return -HTTP_ERR_SSL;
            }
        }
        if(hd->cert_auth == 0){
            SSL_CTX_set_verify(hd->ctx, SSL_VERIFY_NONE, NULL);
        }else{
            SSL_CTX_set_verify(hd->ctx, SSL_VERIFY_PEER, ca_verify_cb);
            SSL_CTX_set_verify_depth(hd->ctx, SSL_DEPTH);
            if(SSL_CTX_load_verify_locations(hd->ctx, hd->cert_path, NULL) != 1) {
                return -HTTP_ERR_SSL;
            }
        }
        SSL_CTX_set_default_passwd_cb_userdata(hd->ctx, hd->passwd);
        if(SSL_CTX_use_certificate_chain_file(hd->ctx, hd->cert_path) == 1){
            PLOG(PLOG_LEVEL_DEBUG,"Load certificate success\n");
        }
        if(SSL_CTX_use_PrivateKey_file(hd->ctx, hd->key_path, SSL_FILETYPE_PEM) == 1) {
            PLOG(PLOG_LEVEL_DEBUG,"Load private key success\n");
        }
        if(SSL_CTX_check_private_key(hd->ctx) == 1) {
            PLOG(PLOG_LEVEL_DEBUG,"Check private key success\n");
        }
        if((hd->ssl = SSL_new(hd->ctx)) == NULL) {
            PLOG(PLOG_LEVEL_DEBUG,"Error: create SSL failure\n");
            return -HTTP_ERR_SSL;
        }
        if(SSL_set_fd(hd->ssl, hd->sk) != 1) {
            PLOG(PLOG_LEVEL_DEBUG,"Error: set SSL fd failure\n");
        }
        if(SSL_connect(hd->ssl) != 1) {
            return -HTTP_ERR_CONN;
        }
        PLOG(PLOG_LEVEL_DEBUG,"Connected to SSL success\n");
    return 0;
}

void destroy_ssl(struct http_data *hd) {
    if(hd->ssl) {
        SSL_set_shutdown(hd->ssl, 2);
        SSL_shutdown(hd->ssl);
        SSL_free(hd->ssl);
    }
    if(hd->ctx) SSL_CTX_free(hd->ctx);
    hd->ssl = NULL;
    hd->ctx = NULL;
}

void destroy_http(struct http_data *hd) {
    if(hd->sk > 0) {
        close(hd->sk);
        hd->sk = -1;
    }
}


void http_clean_hd(struct http_data *hd)
{
    if(hd == NULL) return;
    int i = 0;
    for (i = 0; i < hd->http.header_count; i++) {
        if(hd->http.header[i] != NULL) {
            free(hd->http.header[i]);
            hd->http.header[i] = NULL;
        }
    }
    if(hd->http.body.start != NULL) {
        free(hd->http.body.start);
        hd->http.body.start = NULL;
    }
    if(hd->body_send != NULL) {
        free(hd->body_send);
        hd->body_send = NULL;
    }
    hd->http.content_len = 0;
    hd->http.body.offset = 0;
    hd->http.body.size = 0;
    hd->body_send_len = 0;
}
void http_destroy_hd(struct http_data *hd) {
    if(hd->uri.proto == PROTO_HTTPS){
        destroy_ssl(hd);
        destroy_http(hd);
    }else{
        destroy_http(hd);
    }
    http_clean_hd(hd);
    free(hd);
}

int http_set_user_pass(struct http_data *hd, char *user, char *pass)
{
    if(hd!=NULL && user!=NULL && pass!=NULL) {
        strncpy(hd->username, user, HTTP_USER_LEN);
        strncpy(hd->password, pass, HTTP_PASS_LEN);
        return 0;
    }
    return -HTTP_ERR_PARAM;
}
int http_copy_field(char *in, char *out, int len)
{
    int count = 0;
    if(in != NULL && out != NULL) {
        for(count = 0; count < len; count ++) {
            if(in[count] != '"') {
                out[count] = in[count];
            }else{
                break;
            }
        }
        return 0;
    }
    return -HTTP_ERR_PARAM;
}
int http_parse_auth(struct http_data *hd)
{
    char *ptr;
    char *realm;
    char *nonce;
    char auth_str[HTTP_AUTH_LEN];
    if(http_find_header(hd, "WWW-Authenticate", auth_str)==0) {
        ptr = auth_str;
        if(strncmp(auth_str, "Digest", strlen("Digest") )==0) {
            strcpy(hd->http.auth,"Digest");
            if((realm = strstr(ptr, "realm")) != NULL) {
                realm = realm + strlen("realm:\"");
                http_copy_field(realm, hd->http.realm, HTTP_AUTH_LEN);
            }
            if((nonce = strstr(ptr, "nonce")) != NULL) {
                nonce = nonce + strlen("nonce:\"");
                http_copy_field(nonce, hd->http.nonce, HTTP_AUTH_LEN);
            }
        }else if(strncmp(auth_str, "Basic", strlen("Basic") )==0) {
            strcpy(hd->http.auth,"Basic");
        }
    }
    return 0;
}

int http_set_method(struct http_data *hd, int type)
{
    if(hd == NULL || type < HTTP_GET || type > HTTP_DELETE) {
        return -1;
    }
    hd->http.req_type = type;
    return 0;
}
int http_set_body(struct http_data *hd, void *data, int len) {
    if(hd){
        if(hd->body_send == NULL){
            hd->body_send = malloc(len);
            memcpy(hd->body_send, data, len);
            hd->body_send_len = len;
        }else{
            char *tmp = realloc(hd->body_send, len);
            if(tmp){
                hd->body_send = tmp;
                hd->body_send_len = len;
            }else{
                PLOG(PLOG_LEVEL_DEBUG,"Out of memory\n");
                return -HTTP_ERR_OOM;
            }
        }
        return 0;
    }
    return  -HTTP_ERR_PARAM;
}
int http_send_req(struct http_data *hd) {
    char    *header;
    int     len;
    header = hd->http.req;
    if(hd->http.req_type == HTTP_GET) {
        len = snprintf(header, HTTP_HEADER_LEN, "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "Accept: */*\r\n"
                "User-Agent: Kaija/Agent\r\n"
                "\r\n", hd->uri.path, hd->uri.host);
    }else if(hd->http.req_type == HTTP_POST) {
        len = snprintf(header, HTTP_HEADER_LEN, "POST %s HTTP/1.1\r\n"
                "Host: %s:%d\r\n"
                "Accept: */*\r\n"
                "User-Agent: Kaija/Agent\r\n"
                "Content-Length: %d\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "\r\n", hd->uri.path, hd->uri.host, hd->uri.port, hd->body_send_len);
    }
    if(hd->body_send_len > 0){
        int send_byte = hd->body_send_len + len + 1; // header \r\n body \r\n preserve 4 bytes
        char *http_data = malloc(send_byte);
        if(http_data){
            memcpy(http_data, header, len);
            memcpy(http_data + len , hd->body_send, hd->body_send_len);
            send_byte--;
            PLOG(PLOG_LEVEL_DEBUG,"Data %d bytes send\n", send_byte );
        }else{
            PLOG(PLOG_LEVEL_DEBUG,"Out of memory\n");
            return -HTTP_ERR_OOM;
        }
#ifdef DEBUG_HTTP
        PLOG(PLOG_LEVEL_DEBUG,">>>>>>>>>>>>>>>>>>\n%s>>>>>>>>>>>>>>>>>>\n", http_data);
#endif
        hd->send(hd, http_data, send_byte, HTTP_SEND_TIMEOUT);
    }else{
#ifdef DEBUG_HTTP
        PLOG(PLOG_LEVEL_DEBUG,">>>>>>>>>>>>>>>>>>\n%s>>>>>>>>>>>>>>>>>>\n", header);
#endif
        hd->send(hd, header, len, HTTP_SEND_TIMEOUT);
    }
    return 0;
}

int http_md5sum(char *input, int len, char *out)
{
    int ret = 0, i = 0;
    MD5_CTX ctx;
    char buf[3] = {'\0'};
    unsigned char md5[MD5_DIGEST_LENGTH];
    if(input == NULL || len < 1 || out == NULL)
        return -1;
    MD5_Init(&ctx);
    MD5_Update(&ctx, input, len);
    MD5_Final(md5, &ctx);
    out[0] = '\0';
    for(i=0;i<MD5_DIGEST_LENGTH;i++)
    {
        sprintf(buf, "%02x", md5[i]);
        strcat(out, buf);
    }
    //PLOG(PLOG_LEVEL_DEBUG,"MD5:[%s]\n", out);DER_LEN
    return ret;
}

int http_send_auth_req(struct http_data *hd) {
    char    *header;
    int     len;
    char    ha1[HTTP_NONCE_LEN];
    char    ha2[HTTP_NONCE_LEN];
    char    response[HTTP_NONCE_LEN];
    char    cnonce[HTTP_NONCE_LEN];
    char    str[HTTP_HEADER_LEN];
    memset(cnonce, 0, HTTP_NONCE_LEN);
    memset(str, 0, HTTP_HEADER_LEN);
    len = sprintf(cnonce, "%s:%s:%s",hd->username, hd->http.realm, hd->password);
    http_md5sum(cnonce, len ,ha1);

    header = hd->http.req;
    if(hd->http.req_type == HTTP_GET) {
        memset(str, 0, HTTP_HEADER_LEN);
        len = sprintf(str, "GET:%s",hd->uri.path);
        http_md5sum(str, len ,ha2);
        memset(cnonce, 0, HTTP_NONCE_LEN);
        sprintf(cnonce, "%lld", (long long)time(NULL));
        http_md5sum(cnonce, strlen(cnonce), cnonce);
        memset(str, 0, HTTP_HEADER_LEN);
        len = sprintf(str, "%s:%s:00000001:%s:%s:%s",ha1, hd->http.nonce, cnonce, "auth",ha2);
        http_md5sum(str, len ,response);


        //http_md5sum(str, len ,cnonce);
        len = snprintf(header, HTTP_HEADER_LEN,
            "GET %s HTTP/1.1\r\n"
            "Authorization: %s username=\"%s\", realm=\"%s\","
            "nonce=\"%s\", uri=\"%s\","
            "cnonce=\"%s\", nc=00000001, qop=auth,"
            "response=\"%s\"\r\n"
            "User-Agent: Kaija/Agent\r\n"
            "Host: %s:%d\r\n"
            "Accept: */*\r\n\r\n",
            hd->uri.path,
            hd->http.auth, hd->username, hd->http.realm,
            hd->http.nonce, hd->uri.path,
            cnonce,
            response,
            hd->uri.host,hd->uri.port);
    }else if(hd->http.req_type == HTTP_POST) {
        memset(str, 0, HTTP_HEADER_LEN);
        len = sprintf(str, "POST:%s",hd->uri.path);
        http_md5sum(str, len ,ha2);
        memset(cnonce, 0, HTTP_NONCE_LEN);
        sprintf(cnonce, "%lld", (long long)time(NULL));
        http_md5sum(cnonce, strlen(cnonce), cnonce);
        memset(str, 0, HTTP_HEADER_LEN);
        len = sprintf(str, "%s:%s:00000001:%s:%s:%s",ha1, hd->http.nonce, cnonce, "auth",ha2);
        http_md5sum(str, len ,response);


        //http_md5sum(str, len ,cnonce);
        len = snprintf(header, HTTP_HEADER_LEN,
            "POST %s HTTP/1.1\r\n"
            "Authorization: %s username=\"%s\", realm=\"%s\","
            "nonce=\"%s\", uri=\"%s\","
            "cnonce=\"%s\", nc=00000001, qop=auth,"
            "response=\"%s\"\r\n"
            "User-Agent: Kaija/Agent\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: %d\r\n"
            "Host: %s:%d\r\n"
            "Accept: */*\r\n\r\n",
            hd->uri.path,
            hd->http.auth, hd->username, hd->http.realm,
            hd->http.nonce, hd->uri.path,
            cnonce,
            response,
            hd->body_send_len,
            hd->uri.host,hd->uri.port);
    }
    if(hd->body_send_len > 0){
        int send_byte = hd->body_send_len + len + 1; // header \r\n body \r\n preserve 4 bytes
        char *http_data = malloc(send_byte);
        if(http_data){
            memcpy(http_data, header, len);
            memcpy(http_data + len , hd->body_send, hd->body_send_len);
            send_byte --;
            PLOG(PLOG_LEVEL_DEBUG,"Data %d bytes send\n", send_byte);
        }else{
            PLOG(PLOG_LEVEL_DEBUG,"Out of memory\n");
            return -HTTP_ERR_OOM;
        }
#ifdef DEBUG_HTTP
        PLOG(PLOG_LEVEL_DEBUG,">>>>>>>>>>>>>>>>>>\n%s>>>>>>>>>>>>>>>>>>\n", http_data);
#endif
        hd->send(hd, http_data, send_byte, HTTP_SEND_TIMEOUT);
    }else{
#ifdef DEBUG_HTTP
        PLOG(PLOG_LEVEL_DEBUG,">>>>>>>>>>>>>>>>>>\n%s>>>>>>>>>>>>>>>>>>\n", header);
#endif
        hd->send(hd, header, len, HTTP_SEND_TIMEOUT);
    }
    return 0;
}

int http_add_header(struct http_data *hd, char *header)
{
    char *ver;
    char *code;
    char *phrase;
    if(header) {
        if(strncmp(header, "HTTP/", strlen("HTTP/"))==0) {
            ver = header + 5;
            code = ver;
            while(!isspace(*code)) code ++;
            *code = '\0';
            strcpy(hd->http.version, ver);

            code ++;
            while(isspace(*code))  code++;//skip blank
            phrase = code + 1;
            while(!isspace(*phrase)) phrase ++;
            *phrase = '\0';
            strcpy(hd->http.code, code);

            phrase ++;
            strcpy(hd->http.phrase, phrase);
//printf("HTTP\ncode %s\nver %s\nphrase %s\n", code, ver, phrase);
        }else{
            hd->http.header[hd->http.header_count++] = strdup(header);
        }
    }
    return 0;
}
char *http_skip2break(char *ptr)
{
    while(*ptr != '\r') ptr ++;
    return ptr;
}

int http_alloc_body_size(struct http_data *hd, int length){
    char *tmp;
    if(hd->http.body.start == NULL) {
        hd->http.body.start = malloc(length + 1);
        if(hd->http.body.start == NULL) return -1;
        hd->http.body.size = length;
    }else if(hd->http.body.size - hd->http.body.offset < length){
        tmp = realloc(hd->http.body.start, hd->http.body.offset + length + 1);
        if(tmp == NULL) return -HTTP_ERR_OOM;
        hd->http.body.start = tmp;
        hd->http.body.size = hd->http.body.offset + length;
    }
    return 0;
}

int recv_http_header(struct http_data *hd) {
    int begin = 0;
    int ret = 0;
    int len;
    char *buf = hd->http.buf;
    char *newline;
    int keep = 0;
    for(;;) {
        newline = strstr(buf, "\r\n");
        if(newline == NULL){//First time read.
            len = hd->recv(hd, hd->http.buf + hd->http.buf_offset, sizeof(hd->http.buf) - hd->http.buf_offset -1, keep?HTTP_KEEP_TIMEOUT:HTTP_TIMEOUT);
            if(len > 0)
            {
                hd->http.buf_offset += len;
                hd->http.buf[hd->http.buf_offset] = '\0';
                buf = hd->http.buf;
                keep = 1;
                //PLOG(PLOG_LEVEL_DEBUG,"\n%s\n",hd->http.buf);
                //FIXME if header is not completed
            }else if(len == 0){
                PLOG(PLOG_LEVEL_DEBUG,"recv timeout\n");
                ret = -HTTP_ERR_TIMEOUT;
                break;
            }else{
                PLOG(PLOG_LEVEL_DEBUG,"Recv HTTP header failure \n%d  %d\n%s\n",len ,keep,hd->http.buf );
                ret  = -HTTP_ERR_RECV;
                break;
            }
        }else{
            *newline = '\0';
            newline += 2;
            if(begin == 0){
                //Read first Header EX:HTTP/1.1 200 OK
                http_add_header(hd, buf);
                begin = 1;
            }else{
                if(buf[0] == '\0'){
                    //Reach body
                    if(hd->http.buf + hd->http.buf_offset - newline > 0){
                        memmove(hd->http.buf, newline, hd->http.buf + hd->http.buf_offset - newline +1);
                        hd->http.buf_offset = hd->http.buf + hd->http.buf_offset - newline;
                    }else{
                        hd->http.buf[0] = '\0';
                        hd->http.buf_offset = 0;
                    }
                    //printf("reach body length %d\n---\n%s\n---\n", hd->http.buf_offset, hd->http.buf);
                    break;
                }else{
                    //Header
                    http_add_header(hd, buf);
                }
            }
            buf = newline;
        }
    }
    return ret;
}
int http_recv_normal_body(struct http_data *hd) {
    int len = 0;
    int ret = 0;
    for(;;){
        if(hd->http.buf_offset > 0 ){
            if(hd->http.body.start == NULL){
                hd->http.body.start = malloc(hd->http.content_len + 1);
                if(hd->http.body.start) {
                    memset(hd->http.body.start, 0, hd->http.content_len + 1);
                    memcpy(hd->http.body.start, hd->http.buf, hd->http.buf_offset);
                    hd->http.body.size = hd->http.buf_offset;
                }else{
                    PLOG(PLOG_LEVEL_DEBUG,"Out of memory\n");
                    return -HTTP_ERR_OOM;
                }
            }else{
                //printf("copy data %s\n", hd->http.buf);
                memcpy(hd->http.body.start + hd->http.body.size , hd->http.buf, hd->http.buf_offset);
                hd->http.body.size += hd->http.buf_offset;
                PLOG(PLOG_LEVEL_DEBUG,"body length now %d\n", hd->http.body.size);
            }
        }
        if(hd->http.content_len == hd->http.body.size){
            PLOG(PLOG_LEVEL_DEBUG,"All body downloaded\n");
            break;
        }
        len = hd->recv(hd, hd->http.buf, sizeof(hd->http.buf) - 1, HTTP_TIMEOUT );
        if(len > 0){
            hd->http.buf_offset = len;
        }else{
            PLOG(PLOG_LEVEL_DEBUG,"recv body error\n");
            continue;
            //return -1;
        }
    }
    return ret;
}

int http_recv_chunked_body(struct http_data *hd) {
    int     len = 0;
    int     ret = 0;
    char    *newline;
    char    *ptr;
    char    *tmp;
    char    buf[HTTP_RECV_BUF];
    long    length;
    int     rest_len;
    for(;;){
        if(hd->http.buf_offset > 0) {
            //PLOG(PLOG_LEVEL_DEBUG,"buffer offset %d  %s\n", hd->http.buf_offset, hd->http.buf);
            memset(buf, 0, HTTP_RECV_BUF);
            memcpy(buf, hd->http.buf, hd->http.buf_offset + 1);// Copy a buffer
            ptr = buf;
            //PLOG(PLOG_LEVEL_DEBUG,"buf:%s\n",ptr);
        }else{
            PLOG(PLOG_LEVEL_DEBUG,"Not expected case\n");
            hd->recv(hd, hd->http.buf, sizeof(hd->http.buf) - 1, HTTP_TIMEOUT);
            memset(buf, 0, HTTP_RECV_BUF);
            memcpy(buf, hd->http.buf, hd->http.buf_offset + 1);// Copy a buffer
            ptr = buf;
            break;
        }
        newline = strstr(ptr, "\r\n");
        if(newline == NULL) { // No chunk, copy to body
            if(hd->http.body.start == NULL) {
                hd->http.body.start = malloc(hd->http.buf_offset + 1);
                if(hd->http.body.start){
                    memcpy(hd->http.body.start, hd->http.buf, hd->http.buf_offset);
                    hd->http.body.size = hd->http.buf_offset;
                }else{
                    PLOG(PLOG_LEVEL_DEBUG,"Out of memory\n");
                    return -HTTP_ERR_OOM;
                }
            }else{
                tmp = realloc(hd->http.body.start, hd->http.body.size + hd->http.buf_offset +1);
                if(tmp){
                    hd->http.body.start = tmp;
                    memcpy(hd->http.body.start + hd->http.body.size, hd->http.buf, hd->http.buf_offset);
                    hd->http.body.size += hd->http.buf_offset;
                }else{
                    PLOG(PLOG_LEVEL_DEBUG,"Out of memory\n");
                    return -HTTP_ERR_OOM;
                }
            }
        }else{//parse if body end
            int body_end = 0;
            while(newline != NULL){
                *newline = '\0';
                newline += 2;
                length = strtol (ptr, NULL, 16);
                if(length == 0){
                    //reach body end
                    rest_len = newline - buf;
                    if(rest_len > 0) {
                        body_end = 1;
                    }else{
                        PLOG(PLOG_LEVEL_DEBUG,"error rest length < 0\n");
                        rest_len = 0;
                        body_end = 1;
                    }
                    break;
                }else if(length < 0 || errno == ERANGE){
                    PLOG(PLOG_LEVEL_DEBUG,"Decode chunk error\n");
                    return -HTTP_ERR_DECODE;
                }else{//still chunk keep find \r\n
                    ptr = newline;
                    newline = strstr(ptr, "\r\n");
                }
            }
            if(body_end == 1){
                if(hd->http.body.start == NULL) {
                    hd->http.body.start = malloc(hd->http.buf_offset + 1);
                    memcpy(hd->http.body.start, hd->http.buf, hd->http.buf_offset);
                    hd->http.body.size = rest_len;
                    break;
                }else{
                    tmp = realloc(hd->http.body.start, hd->http.body.size + hd->http.buf_offset + 1);
                    if(tmp){
                        hd->http.body.start = tmp;
                        memcpy(hd->http.body.start + hd->http.body.size, hd->http.buf, hd->http.buf_offset);// Copy rest data
                        hd->http.body.size += rest_len;
                    }else{
                        PLOG(PLOG_LEVEL_DEBUG,"Out of memory\n");
                        ret = -HTTP_ERR_OOM;
                    }
                    break;
                }
            }else{
                if(hd->http.body.start == NULL) {
                    hd->http.body.start = malloc( hd->http.buf_offset +1);
                    memcpy(hd->http.body.start, hd->http.buf,  hd->http.buf_offset);
                    hd->http.body.size += hd->http.buf_offset;
                }else{
                    tmp = realloc(hd->http.body.start, hd->http.body.size + hd->http.buf_offset +1);
                    if(tmp){
                        hd->http.body.start = tmp;
                        memcpy(hd->http.body.start + hd->http.body.size, hd->http.buf, hd->http.buf_offset);// Copy all buffer
                        hd->http.body.size += hd->http.buf_offset;
                    }else{
                        PLOG(PLOG_LEVEL_DEBUG,"Out of memory\n");
                        ret = -HTTP_ERR_OOM;
                    }
                }
            }
        }
        len = hd->recv(hd, hd->http.buf, sizeof(hd->http.buf) - 1, HTTP_TIMEOUT);
        if(len > 0) { // keep recv chunked body
            hd->http.buf_offset = len;
        }else{
            hd->http.buf_offset = 0;
            PLOG(PLOG_LEVEL_DEBUG,"Not expected. We should recv body end before no packet recv\n");
            break;
        }
    }
    return ret;
}
int http_decode_chunk_body(struct http_data *hd){
    int     ret = 0;
    char    *ptr = NULL;
    char    *tmp = NULL;
    int     read = 0;
    char    *newline = NULL;
    long    length;
    if(hd->http.body.size > 0){
        tmp = malloc(hd->http.body.size + 1);
        if(tmp) {
            memset(tmp, 0, hd->http.body.size +1);
            ptr = hd->http.body.start;
            for(;;){
                newline = strstr(ptr, "\r\n");
                if(newline == NULL) {
                    free(tmp);
                    return -1;
                }
                *newline = '\0';
                newline += 2;
                //PLOG(PLOG_LEVEL_DEBUG,"**********%s*******\n", ptr);
                length = strtol (ptr, NULL, 16);
                if(length == 0){
                    //Body end
                    free(hd->http.body.start);
                    hd->http.body.start = tmp;
                    hd->http.content_len = read;
                    break;
                }else if(length < 0  || errno == ERANGE) {
                    free(tmp);
                    return -1;
                }else{
                    memcpy(tmp + read, newline, length);
                    read += length;
                }
                ptr = newline;
            }
        }else{
            return -HTTP_ERR_OOM;
        }
    }
    return ret;
}

int http_recv_resp(struct http_data *hd) {
    char    content_len[HTTP_HEADER_LEN];
    char    encode_type[HTTP_HEADER_LEN];
    char    buf[HTTP_RECV_BUF];
    //char    *head  = buf;
    long    length;
    int     ret;
    //char    *start = buf;
    //int     len;
    //char    *header;
    //char    *next_line;
    //int     header_parsed = 0;
    int     read_count = 0;
    memset(content_len, 0, HTTP_HEADER_LEN);
    memset(encode_type, 0, HTTP_HEADER_LEN);
    memset(hd->http.buf, 0, sizeof(hd->http.buf));
    hd->http.buf_offset = 0;
    hd->http.content_len = 0;
    hd->http.body.size = 0;
    hd->http.body.offset = 0;
    if(hd->http.body.start) {
        free(hd->http.body.start);
        hd->http.body.start = NULL;
    }
    if(1)
    {
        memset(buf, 0, HTTP_RECV_BUF);
        if ((ret = recv_http_header(hd) ) < 0 ){
            PLOG(PLOG_LEVEL_DEBUG,"Header receive failure\n");
            return ret;
        }
        http_find_header(hd, "Content-Length", content_len);
        http_find_header(hd, "Transfer-Encoding", encode_type);
        if(strlen(content_len) > 0){
            length = strtol(content_len, NULL, 10);
            hd->http.content_len = length;
            PLOG(PLOG_LEVEL_DEBUG, "HTTP Content-Length:%ld\n", length);
            if(http_recv_normal_body(hd) == 0){
                return 0;
            }else{
                PLOG(PLOG_LEVEL_DEBUG,"http receive body error\n");
                return -HTTP_ERR_RECV;
            }
        }else if(strncmp(encode_type, "chunked", 7) == 0){
            hd->http.chunked = 1;
            if(http_recv_chunked_body(hd) == 0){
                if(http_decode_chunk_body(hd) ==0 ){
                    if(hd->http.body.start){
                        hd->http.body.start[hd->http.content_len] = '\0';
                        //PLOG(PLOG_LEVEL_DEBUG, "chunked length %d\n",hd->http.content_len);
                        return 0;
                    }else{
                        return -HTTP_ERR_DECODE;
                    }
                }else{
                    PLOG(PLOG_LEVEL_DEBUG,"http decode chunk body error\n");
                    return -HTTP_ERR_DECODE;
                }
            }else{
                PLOG(PLOG_LEVEL_DEBUG,"http receive chunk body error\n");
                return -HTTP_ERR_DECODE;
            }
            //TODO parse chunk data
            PLOG(PLOG_LEVEL_DEBUG,"Parse chunked data here\n");
        }else{
            PLOG(PLOG_LEVEL_DEBUG,"No chunked and no content len\n%s\n");
        }
        read_count ++;
    }
    return 0;
}

int http_perform(struct http_data *hd) {
    int ret = -1;
    char loc[HTTP_HOST_LEN];
    struct addrinfo hints;
    struct addrinfo *server;
    int status;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_INET;
    if(http_host_parse(hd) != 0) {
        PLOG(PLOG_LEVEL_DEBUG,"Error: URL parsing error!\nHOST:%s\nPORT:%d\nPATH:%s\n",
            hd->uri.host, hd->uri.port, hd->uri.path);
#ifdef DEBUG
    }else{
        PLOG(PLOG_LEVEL_DEBUG,"Connect to\nHOST:%s\nPORT:%d\nPATH:%s\n",
            hd->uri.host, hd->uri.port, hd->uri.path);
#endif
    }
    struct timeval tv1, tv2;
    unsigned long long start_utime, end_utime;
    gettimeofday(&tv1,NULL);
PLOG(PLOG_LEVEL_DEBUG, "\n");
    if((status = getaddrinfo(hd->uri.host, NULL, &hints, &server)) != 0){
        PLOG(PLOG_LEVEL_ERROR, "getaddrinfo error %s\n", gai_strerror(status));
        return -HTTP_ERR_CONN;
    }
    gettimeofday(&tv2,NULL);
    start_utime = tv1.tv_sec * 1000000 + tv1.tv_usec;
    end_utime = tv2.tv_sec * 1000000 + tv2.tv_usec;

PLOG(PLOG_LEVEL_DEBUG, "it tooks %llu\n", end_utime - start_utime);
    hd->srv_addr.sin_addr = ((struct sockaddr_in *) (server->ai_addr))->sin_addr;
    hd->srv_addr.sin_family = AF_INET;
    hd->srv_addr.sin_port = htons(hd->uri.port);
    hd->sk = socket(AF_INET, SOCK_STREAM, 0);
    if(hd->sk < 0) {
        PLOG(PLOG_LEVEL_DEBUG,"Error: create socket failure %d\n", hd->sk);
        return -HTTP_ERR_SOCKET;
    }
    freeaddrinfo(server);
	http_socket_reuseaddr(hd->sk);
    //http_nonblock_socket(hd->sk);
    http_socket_sendtimeout(hd->sk, HTTP_TIMEOUT);
    http_socket_recvtimeout(hd->sk, HTTP_TIMEOUT);
    if(connect(hd->sk, (struct sockaddr *)&(hd->srv_addr), sizeof(struct sockaddr)) == -1 &&
         errno != EINPROGRESS) {
        if(connect(hd->sk, (struct sockaddr *)&(hd->srv_addr), sizeof(struct sockaddr)) == -1 &&
            errno != EINPROGRESS) {
            PLOG(PLOG_LEVEL_DEBUG,"Error: Cannot connect to server\n");
            destroy_http(hd);
            return -HTTP_ERR_CONN;
        }
    }
    if(hd->uri.proto == PROTO_HTTPS) {
        if(http_ssl_setup(hd) == -1){
            destroy_ssl(hd);
            destroy_http(hd);
            return -HTTP_ERR_SSL;
        }
    }
    struct http_data *hd2 = NULL;
    for(;;) {
        ret = http_send_req(hd);
        if(ret == 0) {
            ret = http_recv_resp(hd);
            if(ret == 0){
                int code = atoi(hd->http.code);
                switch(code){
                    case 302:
                        PLOG(PLOG_LEVEL_DEBUG,"GOT 302 redirect\n");
                        memset(loc, 0, HTTP_HOST_LEN);
                        http_find_header(hd, "Location:", loc);
                        hd2 = http_create();

                        http_set_uri(hd2, loc);
                        http_perform(hd2);
                        if(hd->http.body.start != NULL) free(hd->http.body.start);

                        hd->http.body.start = malloc(hd2->http.content_len);
                        memcpy(hd->http.body.start, hd2->http.body.start, hd2->http.content_len);
                        http_destroy_hd(hd2);
                        ret = 0;
                        break;
                    case 200:
                        //printf("200 OK\n%s\n", hd->http.body.start);
                        ret = 0;
                        break;
                    case 401:
                        PLOG(PLOG_LEVEL_DEBUG,"GOT 401 Unauthorized\n");
                        http_parse_auth(hd);
                        ret = http_send_auth_req(hd);
                        if(ret == 0) {
                            ret = http_recv_resp(hd);
                            if(ret == 0){
                                return 0;
                            }
                        }
                        break;
                    case 404:
                        break;
                    default:
                        break;
                }
                break;
            }else{
                break;
            }
        }else{
            PLOG(PLOG_LEVEL_DEBUG,"Error: send http request error\n");
        }
    }
    return  ret;
}
