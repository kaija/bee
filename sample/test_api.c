#include <stdio.h>
#include "sm_api.h"

int main(){
    char session[128];
    char uid[32];
    struct msg_service_info info;
    int counter0 = 0;
    int counter1 = 0;
    int counter2 = 0;
    int counter3 = 0;
    while(1){
        if(sm_dev_login(SM_LOGIN_IDPW, "f835dd000003", "gemtek", NULL, NULL, session, uid)!=0){
            counter1 ++;
        }else{
            if(sm_get_msg_info(SM_TYPE_DEVICE, session, &info) != 0){
                counter2 ++;
            }else{
                if(sm_send_msg(session ,"600000125", "HA-45058956","test", SM_MSG_TYPE_RT) !=0){
                    counter3 ++;
                }
            }
        }
        counter0 ++;
        printf("====================================================================\n");
        printf("Total : %d login error: %d get service error %d send msg error %d\n", counter0, counter1, counter2, counter3);
        printf("====================================================================\n");
    }
    return 0;
}
