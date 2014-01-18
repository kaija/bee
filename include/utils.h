#ifndef __BEE_UTILS_H
#define __BEE_UTILS_H

#ifndef MAX
#define MAX(a,b) a>b?a:b
#endif

#define BEE_TLV_OFFSET  6

char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length);
char *base64_decode(const char *data,
                    size_t input_length,
                    size_t *output_length);
void noly_hexdump(unsigned char *start, int len);
int noly_socket_set_nonblock(int sk);
int noly_tcp_socket(int port, int max_cli);
int noly_udp_rand_socket(int *port);
int noly_udp_sender(char *addr, int port, char *payload, int len);
int noly_udp_socket_from(int start, int *port);
int noly_tcp_socket_from(int start, int *port, int max_cli);
int json_str_get_obj(char *str, char *key, char *val, int len);

#endif
