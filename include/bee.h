#ifndef __BEE_H
#define __BEE_H

#define BEE_ID_LEN      64
#define BEE_PW_LEN      64
#define BEE_IP_LEN      32
#define BEE_NAME_LEN    32
#define BEE_URL_LEN     256
#define BEE_SESS_LEN    128
#define BEE_SRV_TYPE    "ST_P2P"

enum{
    BEE_API_OK,
    BEE_API_FAIL
};

struct bee_nbr
{
    char                id[BEE_ID_LEN];
    char                ip[BEE_IP_LEN];
    char                name[BEE_NAME_LEN];
    struct bee_nbr      *next;
};

struct bee_user_list{
    char                **user_list;
    int                 user_num;
};

#endif
