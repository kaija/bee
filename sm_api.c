#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <openssl/ssl.h>

#include "sm_api.h"
#include "http.h"
#include "log.h"
#include "parson.h"

int sm_ret_code_handler(char *username, char *ret_code);

static struct http_setup sm_setup;

pthread_mutex_t sm_api_mutex;


char from_hex(char ch) {
    return isdigit(ch) ? ch - '0' : tolower(ch) - 'A' + 10;
}

char to_hex(char code) {
    static char hex[] = "0123456789ABCDEF";
    return hex[code & 15];
}

char *url_encode(char *str) {
    char *pstr = str, *buf = malloc(strlen(str) * 3 + 1), *pbuf = buf;
    while (*pstr) {
    if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~')
        *pbuf++ = *pstr;
    else if (*pstr == ' ')
        *pbuf++ = '+';
    else
        *pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
    pstr++;
    }
    *pbuf = '\0';
    return buf;
}

char *url_decode(char *str) {
    char *pstr = str, *buf = malloc(strlen(str) + 1), *pbuf = buf;
    while (*pstr) {
        if (*pstr == '%') {
            if (pstr[1] && pstr[2]) {
                *pbuf++ = from_hex(pstr[1]) << 4 | from_hex(pstr[2]);
                pstr += 2;
            }
        } else if (*pstr == '+') {
            *pbuf++ = ' ';
        } else {
            *pbuf++ = *pstr;
        }
        pstr++;
    }
    *pbuf = '\0';
    return buf;
}

int init_http_body(struct http_body *s) {
    s->len = 0;
    s->body = malloc(s->len+1);
    if (s->body == NULL) {
        PLOG(PLOG_LEVEL_ERROR, "malloc() failed\n");
        return -1;
    }
    memset(s->body, 0, s->len + 1);
    s->body[0] = '\0';
    return 0;
}

void free_hb(struct http_body *hb)
{
    if(hb != NULL){
        if(hb->body != NULL){
            free(hb->body);
        }
        free(hb);
    }
}

int body_object_get_field(JSON_Object *obj, char *field, char *data, int data_len)
{
    if(!obj) return -1;

    size_t obj_count = json_object_get_count(obj);
    size_t i;
    int ret = -1;
    for(i = 0; i < obj_count; i++){
        const char *name = json_object_get_name(obj, i);
        if(name){
            JSON_Object *sub_obj = json_object_get_object(obj, name);
            if(sub_obj){
                ret = body_object_get_field(sub_obj, field, data, data_len);
                if(ret == 0) break;
            }else{
                if(strcmp(field, name) == 0){
                    if(strcmp(field, "code") == 0){
                        double res = json_object_get_number(obj, name);
                        if(res){
                            sprintf(data, "%d", (int)res);
                        }
                    }else{
                        const char *res = json_object_get_string(obj, name);
                        if(res){
                            strncpy(data, res, data_len);
                        }
                    }
                    return 0;
                }
            }
        }
    }
    return ret;
}

int body_get_field(char *body, char *field, char *data, int data_len)
{
    if(!field || !data || !body) return -1;
    JSON_Value *js_value = NULL;
    JSON_Object *js_object;
    int res = -1;
    js_value = json_parse_string(body);
    if(json_value_get_type(js_value) == JSONObject){
        js_object = json_value_get_object(js_value);
        res = body_object_get_field(js_object, field, data, data_len);
    }
    json_value_free(js_value);
    return res;
}



struct http_body *http_post(char *url, char *data, int len, int method)
{
    pthread_mutex_lock(&sm_api_mutex);
    if(url == NULL) return NULL;
    struct http_body *hb = malloc(sizeof(struct http_body));;
    if(hb == NULL) return NULL;
    memset(hb, 0, sizeof(struct http_body));
    hb->body = NULL;
    struct http_data *hd = http_create();
    if(hd) {
        http_set_uri(hd, url);
        if(method == HTTP_GET) {
            http_set_method(hd, HTTP_GET);
        }else if(method == HTTP_POST){
            http_set_method(hd, HTTP_POST);
        }
        if(strlen(sm_setup.username) > 0) {
            http_set_user_pass(hd, sm_setup.username, sm_setup.password);
        }
        if(strlen(sm_setup.ca_path) > 0) {
            http_set_cert_path(hd, sm_setup.ca_path, 0);
        }
        if(strlen(sm_setup.key_path) > 0) {
            http_set_key_path(hd, sm_setup.key_path, sm_setup.password);
        }
        if(data) {
            http_set_body(hd, data, len);
        }
        if(http_perform(hd) == 0){
            if(hb->body == NULL) {
                hb->body = malloc(hd->http.content_len + 1);
                if(hb->body){
                    memcpy(hb->body, hd->http.body.start, hd->http.content_len);
                    hb->len = hd->http.content_len;
                    hb->body[hb->len] = '\0';
                }else{
                    PLOG(PLOG_LEVEL_ERROR, "Out of memory\n");
                }
            }
        }else{
            if(hb) free(hb);
            hb = NULL;
        }
        http_destroy_hd(hd);
    }
    pthread_mutex_unlock(&sm_api_mutex);
    return hb;
}

int sm_api_init(){
    if(pthread_mutex_init(&sm_api_mutex, NULL) != 0){
        return -1;
    }
    return 0;
}

int sm_login(int login_type, char *username, char *password, char *ca_path, char *key_path, char *sess, char* uid) {
    char url[HTTP_URL_LEN];
    char ret_code[HTTP_RET_LEN] = {0};
    int ret = 0;
    if(login_type == SM_LOGIN_IDPW){
        if(username) {
            strncpy(sm_setup.username, username, HTTP_USERNAME_LEN);
        }
    }else if(login_type == SM_LOGIN_CERT){
        if(ca_path) {
            strncpy(sm_setup.ca_path, ca_path, HTTP_CA_PATH_LEN);
        }
        if(key_path) {
            strncpy(sm_setup.key_path, key_path, HTTP_KEY_PATH_LEN);
        }
    }
    if(password) {
        strncpy(sm_setup.password, password, HTTP_PASSWORD_LEN);
    }
    struct http_body *hb;
    snprintf(url, HTTP_URL_LEN, "%s/v1/user/login",SM_API_SECURE_SERVER);
    hb = http_post(url,NULL, 0, HTTP_GET);
    if(hb) {
        PLOG(PLOG_LEVEL_INFO, "body\n%s\n", hb->body);
        if(sess && hb->body) {
            if(strstr(hb->body, "Unauthorized") != NULL){
                PLOG(PLOG_LEVEL_DEBUG, "Your id and password not correct\n");
                sm_status_handle(username, 0, SM_AUTH_FAILURE);
                ret = -1;
            }else{
                if(body_get_field(hb->body, "code", ret_code, HTTP_RET_LEN)!=-1){
                    int code = atoi(ret_code);
                    if((code == 1221) || (code == 1211)){
                        if(body_get_field(hb->body, "token", sess, SM_SESS_LEN)==-1){
                            sm_status_handle(username, 0, SM_LOGIN_FAILURE);
                            PLOG(PLOG_LEVEL_DEBUG, "Login error cannot get token\n");
                            ret = -1;
                        }else{
                            if (body_get_field(hb->body, "uid", uid, HTTP_USERNAME_LEN) == -1) {
                                PLOG(PLOG_LEVEL_WARN, "Cannot get uid!\n");
                            }
                            sm_status_handle(username, 0, SM_LOGIN_SUCCESS);
                            PLOG(PLOG_LEVEL_INFO, "Login success token:'%s', uid:'%s'\n", sess, uid);
                        }
                    }else{
                        sm_ret_code_handler(username, ret_code);
                        ret = -1;
                    }
                }else{
                    PLOG(PLOG_LEVEL_DEBUG, "login failure: can not get return code\n");
                    sm_status_handle(username, 0, SM_LOGIN_FAILURE);
                    ret = -1;
                }
            }
        }
        free_hb(hb);
    }else{
        PLOG(PLOG_LEVEL_DEBUG, "login failure: connection failure\n");
        sm_status_handle(username, 0, SM_LOGIN_FAILURE);   // TODO: return status 'HUZZA_SM_CONNECTION_FAILURE'
        ret = -1;
    }
    return ret;
}

int sm_send_msg(char *sess ,char *dst, char *api_key, char *msg, int type) {
    char url[HTTP_URL_LEN];
    char ret_code[HTTP_RET_LEN];
    if(!sess || !dst || !msg) return -1;
    int body_len = 0;
    struct http_body *hb;
    char body[HTTP_BODY_SIZE];
    memset(body, 0, HTTP_BODY_SIZE);
    char *session = url_encode(sess);
    char *dest = url_encode(dst);
    if(session && dest) {
        if(type == SM_MSG_TYPE_RT){
            body_len = snprintf(body, HTTP_BODY_SIZE, "token=%s&dst=%s&text=%s&qos=1&expire=8640000&type=1&api_key=%s", session, dest, msg, api_key);
        }else{
            body_len = snprintf(body, HTTP_BODY_SIZE, "token=%s&dst=%s&text=%s&qos=1&expire=8640000&type=0&api_key=%s", session, dest, msg, api_key);
        }
        if(session) free(session);
        if(dest) free(dest);
    }
    PLOG(PLOG_LEVEL_INFO, "SEND BODY |%s|\n", body);
    snprintf(url, HTTP_URL_LEN, "%s/mec_msg/v1/send",SM_API_SERVER);
    hb = http_post(url, body, body_len, HTTP_POST);
    //hb = http_post("https://www-dev.securepilot.com/msg/v1/send",body, 1);
    if(hb) {
        PLOG(PLOG_LEVEL_INFO, "body\n%s\n", hb->body);
        if(hb->body){
            if(body_get_field(hb->body, "code", ret_code, HTTP_RET_LEN)!=-1){
                sm_ret_code_handler("unknow", ret_code);
            }else{
                PLOG(PLOG_LEVEL_DEBUG, "sm send failure: can not get return code\n");
                sm_status_handle("unknow", 0, SM_SEND_FAILURE);
            }
        }
        free_hb(hb);
    }
    return 0;
}

char *sm_get_msg(char *sess, char *api_key, int serial) {
    char url[HTTP_URL_LEN];
    char ret_code[HTTP_RET_LEN];
    if(!sess) return  NULL;
    char *res = NULL;
    struct http_body *hb;
    int body_len = 0;
    char body[HTTP_BODY_SIZE];
    memset(body, 0, HTTP_BODY_SIZE);
    char *session = url_encode(sess);
    if(session) {
        body_len = snprintf(body, HTTP_BODY_SIZE, "token=%s&serial=%d&api_key=%s", session, serial, api_key);
        free(session);
    }
    snprintf(url, HTTP_URL_LEN, "%s/mec_msg/v1/get",SM_API_SERVER);
    hb = http_post(url, body, body_len, HTTP_POST);
    if(hb) {
        if(hb->body){
            PLOG(PLOG_LEVEL_DEBUG, "body\n%s\n", hb->body);
            if(body_get_field(hb->body, "code", ret_code, HTTP_RET_LEN)!=-1){
                res = malloc(hb->len+1);
                if(res){
                    memcpy(res, hb->body, hb->len);
                    res[hb->len] = 0;
                }
                sm_ret_code_handler(sm_setup.username, ret_code);
            }else{
                PLOG(PLOG_LEVEL_DEBUG, "sm send failure: can not get return code\n");
                sm_status_handle(sm_setup.username, 0, SM_SEND_FAILURE);
            }
        }
        free_hb(hb);
    }
    return res;
}

int sm_get_msg_info(int type, char *sess, struct msg_service_info *info) {
    char url[HTTP_URL_LEN];
    if(!sess) return  -1;
    int res = -1;
    struct http_body *hb;
    int body_len = 0;
    char body[HTTP_BODY_SIZE];
    memset(body, 0, HTTP_BODY_SIZE);
    char *session = url_encode(sess);
    if(session) {
        body_len = snprintf(body, HTTP_BODY_SIZE, "token=%s&service=MSG", session);
        free(session);
    }
    if(type == SM_TYPE_USER){
        snprintf(url, HTTP_URL_LEN, "%s/v1/user/get_service_info",SM_API_SERVER);
    }else{
        snprintf(url, HTTP_URL_LEN, "%s/v1/device/get_service_info",SM_API_SERVER);
    }
    hb = http_post(url, body, body_len, HTTP_POST);
    if(hb) {
        PLOG(PLOG_LEVEL_DEBUG, "body\n%s\n", hb->body);
        if(body_get_field(hb->body, "mqtt_server", info->mqtt_ip, HTTP_IP_LEN)==-1){
            res = -1;
            goto err;
        }
        char port[8];
        if(body_get_field(hb->body, "mqtt_server_port", port, 8)==-1){
            res = -1;
            goto err;
        }
        info->mqtt_port = atoi(port);
        if(body_get_field(hb->body, "id", info->mqtt_id, HTTP_USERNAME_LEN)==-1){
            res = -1;
            goto err;
        }
        if(body_get_field(hb->body, "pwd", info->mqtt_pw, HTTP_PASSWORD_LEN)==-1){
            res = -1;
            goto err;
        }
err:
        free_hb(hb);
        res = 0;
    }
    return res;
}

int sm_ret_code_handler(char *username, char *ret_code)
{
    int code = atoi(ret_code);
    switch(code){
        case 1401:
            PLOG(PLOG_LEVEL_ERROR, "Service management internal server error (DB connection)\n");
            sm_status_handle(username, 0, SM_SERV_ERROR);
            break;
        case 1402:
            PLOG(PLOG_LEVEL_ERROR, "service management DB failure\n");
            sm_status_handle(username, 0, SM_DB_ERROR);
            break;
        case 1403:
            PLOG(PLOG_LEVEL_ERROR, "service management internal failure\n");
            sm_status_handle(username, 0, SM_SERV_ERROR);
            break;
        case 1431:
            PLOG(PLOG_LEVEL_DEBUG, "service management session timeout\n");
            sm_status_handle(username, 0, SM_SESS_TIMEOUT);
            break;
        case 2421:
            PLOG(PLOG_LEVEL_ERROR, "service management p2p sned failure\n");
            sm_status_handle(username, 0, SM_SEND_FAILURE);
            break;
        case 2422:
            PLOG(PLOG_LEVEL_ERROR, "service management p2p get failure\n");
            sm_status_handle(username, 0, SM_GET_FAILURE);
            break;
        default:
            break;
    }
    return 0;
}
int sm_dev_login(int login_type, char *username, char *password, char *ca_path, char *key_path, char *sess, char *uid) {
    char url[HTTP_URL_LEN];
    char ret_code[HTTP_RET_LEN] = {0};
    int ret = 0;
    if(login_type == SM_LOGIN_IDPW){
        if(username) {
            strncpy(sm_setup.username, username, HTTP_USERNAME_LEN);
        }
    }else if(login_type == SM_LOGIN_CERT){
        if(ca_path) {
            strncpy(sm_setup.ca_path, ca_path, HTTP_CA_PATH_LEN);
        }
        if(key_path) {
            strncpy(sm_setup.key_path, key_path, HTTP_KEY_PATH_LEN);
        }
    }
    if(password) {
        strncpy(sm_setup.password, password, HTTP_PASSWORD_LEN);
    }
    struct http_body *hb;
    snprintf(url, HTTP_URL_LEN, "%s/v1/device/login",SM_API_SECURE_SERVER);
    hb = http_post(url,NULL, 0, HTTP_GET);
    if(hb) {
        PLOG(PLOG_LEVEL_DEBUG, "Recv from SM:\n%s\n", hb->body);
        if(sess && hb->body) {
            if(strstr(hb->body, "Unauthorized") != NULL){
                PLOG(PLOG_LEVEL_DEBUG, "Your id and password not correct\n");
                sm_status_handle(username, 0, SM_AUTH_FAILURE);
                ret = -1;
            }else{
                if(body_get_field(hb->body, "code", ret_code, HTTP_RET_LEN)!=-1){
                    int code = atoi(ret_code);
                    if((code == 1221) || (code == 1211)){
                        if(body_get_field(hb->body, "token", sess, SM_SESS_LEN)==-1){
                            sm_status_handle(username, 0, SM_LOGIN_FAILURE);
                            PLOG(PLOG_LEVEL_DEBUG, "Login error cannot get token\n");
                            ret = -1;
                        }else{
                            if (body_get_field(hb->body, "gid", uid, SM_UID_LEN) == -1) {
                                PLOG(PLOG_LEVEL_WARN, "Cannot get uid!\n");
                            }
                            sm_status_handle(username, 0, SM_LOGIN_SUCCESS);
                            PLOG(PLOG_LEVEL_INFO, "Login success token:'%s'\n", sess);
                        }
                    }else{
                        sm_ret_code_handler(username, ret_code);
                        ret = -1;
                    }
                }else{
                    PLOG(PLOG_LEVEL_DEBUG, "login failure: can not get return code\n");
                    sm_status_handle(username, 0, SM_LOGIN_FAILURE);
                    ret = -1;
                }
            }
        }
        free_hb(hb);
    }else{
        PLOG(PLOG_LEVEL_DEBUG, "login failure: connection failure\n");
        sm_status_handle(username, 0, SM_LOGIN_FAILURE);   // TODO: return status 'HUZZA_SM_CONNECTION_FAILURE'
        ret = -1;
    }
    return ret;
}

int sm_get_uid(char *cert_path, char *uid, char *sm_id)
{
    if(!cert_path || !uid) return -1;
    FILE *fpem;
    X509 *cert;
    X509_NAME *subjName;

    if( !(fpem = fopen(cert_path, "r")) ){
        PLOG(PLOG_LEVEL_ERROR, "Couldn't open the PEM file\n");
        return -1;
    }

    if( !(cert = PEM_read_X509(fpem, NULL, NULL, NULL)) ){
        PLOG(PLOG_LEVEL_ERROR, "Fail to read the PEM file\n");
        fclose(fpem);
        return -1;
    }

    if( !( subjName = X509_get_subject_name( cert ))){
        PLOG(PLOG_LEVEL_ERROR, "X509_get_subject_name failed" );
        fclose(fpem);
        return -1;
    }

    X509_NAME_ENTRY *entry = X509_NAME_get_entry( subjName, 0 );
    ASN1_STRING *entryData = X509_NAME_ENTRY_get_data( entry );

    unsigned char *utf8;
    int length = ASN1_STRING_to_UTF8( &utf8, entryData );
    if(length <= 0) return -1;
    strncpy(uid, (char *)utf8, HTTP_USERNAME_LEN);
    OPENSSL_free( utf8 );

    entry = X509_NAME_get_entry( subjName, 1 );
    entryData = X509_NAME_ENTRY_get_data( entry );
    length = ASN1_STRING_to_UTF8( &utf8, entryData );
    if(length <= 0) return -1;
    strncpy(sm_id, (char *)utf8, HTTP_USERNAME_LEN);

    OPENSSL_free( utf8 );
    fclose(fpem);
    return 0;
}

int sm_get_rly_info(int type, char *sess, struct rly_service_info *info) {
    char url[HTTP_URL_LEN];
    if(!sess) return  -1;
    int res = 0;
    struct http_body *hb;
    int body_len = 0;
    char body[HTTP_BODY_SIZE];
    memset(body, 0, HTTP_BODY_SIZE);
    char *session = url_encode(sess);
    if(session) {
        body_len = snprintf(body, HTTP_BODY_SIZE, "token=%s&service=RELAY", session);
        free(session);
    }
    if(type == SM_TYPE_USER){
        snprintf(url, HTTP_URL_LEN, "%s/v1/user/get_service_info",SM_API_SERVER);
    }else{
        snprintf(url, HTTP_URL_LEN, "%s/v1/device/get_service_info",SM_API_SERVER);
    }
    hb = http_post(url, body, body_len, HTTP_POST);
    if(hb) {
        //printf("body\n%s\n",hb->body);
        if(body_get_field(hb->body, "relay_server", info->relay_ip, HTTP_IP_LEN)==-1){
            res = -1;
        }
        char port[8] = {0};
        if(body_get_field(hb->body, "relay_server_port", port, 8)==-1){
            res = -1;
        }
        info->relay_port = atoi(port);
        if(body_get_field(hb->body, "id", info->relay_id, HTTP_USERNAME_LEN)==-1){
        }
        if(body_get_field(hb->body, "pwd", info->relay_pw, HTTP_PASSWORD_LEN)==-1){
            res = -1;
        }
        free_hb(hb);
    }
    return res;
}

static char sm_sha1[SHA_DIGEST_LENGTH*2+2];

char *SM_SHA1(char *api_secret, time_t now){
    char hash[64];
    snprintf(hash, 64, "%s%ld", api_secret,now);
    printf("HASH src: %s\n", hash);
    unsigned char sha[SHA_DIGEST_LENGTH];
    memset(&sm_sha1, 0, SHA_DIGEST_LENGTH*2 + 2);
    SHA1((unsigned char*)hash, strlen(hash),sha);
/*
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, (unsigned char *)hash, strlen(hash));
    SHA1_Final(sha, &ctx);
*/
    int i;
    for(i=0;i<SHA_DIGEST_LENGTH;i++){
        sprintf(sm_sha1 + i*2, "%02x", sha[i]);
    }
    printf("SHA1 %s\n", sm_sha1);
    return sm_sha1;
}
int sm_get_user_list(char *mac, char *api_key, char *api_sec, char ***result, int *user_num) {
    char url[HTTP_URL_LEN];
    if(!mac || !api_key || !api_sec ) return -1;
    int res = -1;
    struct http_body *hb;
    int body_len = 0;
    char body[HTTP_BODY_SIZE];
    memset(body, 0, HTTP_BODY_SIZE);
    time_t now = time(NULL);
    body_len = snprintf(body, HTTP_BODY_SIZE, "device_id=%s&api_key=%s&api_token=%s&time=%ld", mac, api_key, SM_SHA1(api_sec, now), now);
    snprintf(url, HTTP_URL_LEN, "%s/v1/device/get_user_list",SM_API_SERVER);
    hb = http_post(url, body, body_len, HTTP_POST);
    if(hb) {
        JSON_Value *js_value = NULL;
        JSON_Object *js_object, *js_sub_object;
        JSON_Array *js_array;
        size_t i, array_size;
        js_value = json_parse_string(hb->body);
        if(json_value_get_type(js_value) == JSONObject){
            js_object = json_value_get_object(js_value);
            js_array = json_object_get_array(js_object, "user_list");
            array_size = json_array_get_count(js_array);
            *user_num = array_size;
            *result = (char **)malloc(array_size*sizeof(char *));
            if(js_array != NULL){
                for(i = 0; i < array_size; i++){
                    //FIXME check null pointer
                    (*result)[i] = (char *)malloc(HTTP_USERNAME_LEN);
                    memset((*result)[i], 0, HTTP_USERNAME_LEN);
                    js_sub_object = json_array_get_object(js_array, i);
                    const char *str = json_object_get_string(js_sub_object, "uid");
                    memcpy((*result)[i], str, HTTP_USERNAME_LEN);
                }
                res = 0;
            }
        }
        json_value_free(js_value);
        free_hb(hb);
    }
    return res;
}

int sm_add_user(char *token, char *user_id, char *dev_info, char *api_key, char *api_sec, char *req_key)
{
    char url[HTTP_URL_LEN];
    if(!token || !user_id || !api_key || !api_sec || !req_key) return -1;
    int res = -1;
    char ret_code[HTTP_RET_LEN] = {0};
    struct http_body *hb;
    int body_len = 0;
    char body[HTTP_BODY_SIZE];
    memset(body, 0, HTTP_BODY_SIZE);
    time_t now = time(NULL);
    body_len = snprintf(body, HTTP_BODY_SIZE, "token=%s&user_id=%s&api_key=%s&api_token=%s&time=%ld&req_key=%s", token, user_id, api_key, SM_SHA1(api_sec, now), now, req_key);
    snprintf(url, HTTP_URL_LEN, "%s/v1/device/add_user",SM_API_SERVER);
    hb = http_post(url, body, body_len, HTTP_POST);
    if(hb) {
        if(body_get_field(hb->body, "code", ret_code, HTTP_RET_LEN)!=-1){
            int code = atoi(ret_code);
            if(code == 1231){
                PLOG(PLOG_LEVEL_INFO, "User and device binding successful\n");
            }else{
                PLOG(PLOG_LEVEL_DEBUG, "User and device binding fail, ret: %d\n", code);
            }
        }
    }
    return res;
}

int sm_rm_user(char *token, char *user_id, char *api_key, char *api_sec)
{
    char url[HTTP_URL_LEN];
    if(!token || !user_id || !api_key || !api_sec ) return -1;
    int res = -1;
    char ret_code[HTTP_RET_LEN] = {0};
    struct http_body *hb;
    int body_len = 0;
    char body[HTTP_BODY_SIZE];
    memset(body, 0, HTTP_BODY_SIZE);
    time_t now = time(NULL);
    body_len = snprintf(body, HTTP_BODY_SIZE, "token=%s&user_id=%s&api_key=%s&api_token=%s&time=%ld", token, user_id, api_key, SM_SHA1(api_sec, now), now);
    snprintf(url, HTTP_URL_LEN, "%s/v1/device/rm_user",SM_API_SERVER);
    hb = http_post(url, body, body_len, HTTP_POST);
    if(hb) {
        if(body_get_field(hb->body, "code", ret_code, HTTP_RET_LEN)!=-1){
            int code = atoi(ret_code);
            if(code == 1234){
                PLOG(PLOG_LEVEL_INFO, "User and device unbinding successful\n");
            }else{
                PLOG(PLOG_LEVEL_DEBUG, "User and device unbinding fail, ret: %d\n", code);
            }
        }
    }
    return res;
}
int sm_status_handle(char *pid, int cid, int status)
{
    return 0;
}
