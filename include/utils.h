#ifndef __BEE_UTILS_H
#define __BEE_UTILS_H
#include <stdint.h>
#include "parson.h"

#ifndef MAX
#define MAX(a,b) a>b?a:b
#endif

#define BEE_TLV_OFFSET  6

struct noly_json_array
{
    JSON_Array      *array;
    JSON_Value      *js_val;
    int             count;
    int             size;
};

struct noly_json_obj
{
    JSON_Object     *obj;
    int             size;
};


char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length);
char *base64_decode(const char *data,
                    size_t input_length,
                    size_t *output_length);
void noly_hexdump(unsigned char *start, int len);
void noly_set_tcp_nodelay(int sk);
int noly_socket_set_nonblock(int sk);
int noly_tcp_socket(int port, int max_cli);
int noly_udp_rand_socket(int *port);
int noly_udp_sender(char *addr, int port, char *payload, int len);
int noly_udp_socket_from(int start, int *port);
int noly_tcp_socket_from(int start, int *port, int max_cli);
uint16_t bee_pkt_csum(const void *buff, size_t len);

int noly_json_obj_get_obj(JSON_Object *obj, char *key, char *val, int len);
JSON_Array *noly_json_obj_get_array(JSON_Object *obj, char *key);
struct noly_json_array *noly_json_str_get_array(char *str, char *key);
struct noly_json_obj *noly_json_array_get_obj(struct noly_json_array *array, int index);
int noly_json_array_get_str(struct noly_json_array *array, int index, char **str, int *len);
int json_array_release(struct noly_json_array *array);
int noly_json_str_get_str(const char *str, char *key, char *val, int len);

int bee_tlv_appender(unsigned long type, unsigned long len, void *value, void **output, int rlen);
int bee_tlv_creator(unsigned long type, unsigned long len, void *value, void **output);
int bee_tlv_parser(void *input, unsigned long *type, void **value, unsigned long *len);

#endif
