#ifndef __SM_API_H
#define __SM_API_H

//#define SM_API_SERVER "http://www-dev.securepilot.com:8080"
#define SM_API_SERVER "https://s5.securepilot.com"
#define SM_API_SECURE_SERVER "https://s5.securepilot.com"

enum{
    SM_MSG_TYPE_DEFAULT,
    SM_MSG_TYPE_RT,
    SM_MSG_TYPE_MAX
};

enum{
    SM_LOGIN_IDPW,
    SM_LOGIN_CERT
};

enum{
    SM_TYPE_USER,
    SM_TYPE_DEVICE
};

//NOTICE: Map the SM error code to bee library error code
enum{
    SM_LOGIN_SUCCESS=0,
    SM_LOGIN_FAILURE=1,
    SM_AUTH_FAILURE=401,
    SM_GET_FAILURE=402,
    SM_SEND_FAILURE=403,
    SM_SESS_TIMEOUT=404,
    SM_BAD_RESP=405,
    SM_SERV_ERROR=406,
    SM_CONN_ERROR=407,
    SM_DB_ERROR=408,
    SM_LIB_ERROR=409,
    SM_PARAM_ERROR=410,
    SM_UNKNOWN_ERROR
};

#define HTTP_MIME_TEXT      0
#define HTTP_MIME_JSON      1

#define HTTP_USERNAME_LEN   64
#define HTTP_PASSWORD_LEN   64

#define HTTP_CA_PATH_LEN    256
#define HTTP_KEY_PATH_LEN   256
#define HTTP_BODY_SIZE      2048
#define HTTP_URL_LEN        256
#define HTTP_IP_LEN         32
#define HTTP_RET_LEN        16

#define SM_SESS_LEN         128
#define SM_CERT_LEN         4096

#define SM_NAME_LEN         64
#define SM_EMAIL_LEN        64
#define SM_UID_LEN          64
#define SM_PW_LEN           64
#define SM_PIN_LEN          16
#define SM_USERKEY_LEN      64
#define SM_MOBILE_LEN       32

#define SM_API_KEY_LEN      64
#define SM_API_SEC_LEN      64


struct http_setup {
    char    username[HTTP_USERNAME_LEN];
    char    password[HTTP_PASSWORD_LEN];
    char    ca_path[HTTP_CA_PATH_LEN];
    char    key_path[HTTP_KEY_PATH_LEN];
    char    session[SM_SESS_LEN];
};

struct http_body {
    char    *body;
    size_t  len;
};

struct rly_service_info{
	char relay_ip[HTTP_IP_LEN];
	int  relay_port;
	char relay_id[HTTP_USERNAME_LEN];
	char relay_pw[HTTP_PASSWORD_LEN];
};

struct msg_service_info{
    char mqtt_ip[HTTP_IP_LEN];
    int  mqtt_port;
    char mqtt_id[HTTP_USERNAME_LEN];
    char mqtt_pw[HTTP_PASSWORD_LEN];
};

struct sm_user_profile{
    char    name[SM_NAME_LEN];
    char    uid[SM_UID_LEN];
    char    email[SM_EMAIL_LEN];
    char    user_key[SM_USERKEY_LEN];
    char    mobile[SM_MOBILE_LEN];
};

struct sm_dev_account {
    char    username[SM_NAME_LEN];//the device mac address
    char    password[SM_PW_LEN];
    char    uid[SM_UID_LEN];
    char    pin[SM_PIN_LEN];
    char    cert[SM_CERT_LEN];
    char    pkey[SM_CERT_LEN];
};

char *url_encode(char *str);
char *url_decode(char *str);

struct http_body *http_post(char *url, char *data, int len, int method);
int sm_api_init();
int sm_login(int login_type, char *username, char *password, char *ca_path, char *key_path, char *sess, char *uid);
int sm_dev_login(int login_type, char *username, char *password, char *ca_path, char *key_path, char *sess, char *uid);
int sm_send_msg(char *sess ,char *dst, char *api_key, char *msg, int type);
int sm_get_msg(char *sess, char *api_key, int serial, char **msg);
int sm_get_msg_info(int type, char *sess, struct msg_service_info *info);
int sm_get_uid(char *cert_path, char *uid, char *sm_id);
int sm_get_rly_info(int type, char *sess, struct rly_service_info *info);
int sm_get_user_list(char *token, char *api_key, struct sm_user_profile **result, int *user_num);
int sm_add_user(char *token, char *user_id, char *dev_info, char *api_key, char *api_sec, char *req_key);
int sm_rm_user(char *token, char *user_id, char *api_key, char *api_sec);
int sm_new_device(char *cert, char *pkey, char *pw, char *mac, char *pin, struct sm_dev_account *result);
int sm_device_activation(char *dev_id);
int sm_status_handle(char *pid, int cid, int status);
#endif
