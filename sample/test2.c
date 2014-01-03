#include <stdio.h>
#include <unistd.h>
#include "bee.h"
#include "simclist.h"
int main()
{
    list_t l;
    while(1){
        list_init(&l);
        usleep(100000);
    }


    bee_user_init();
    bee_user_login_id_pw("kaija.chang@gmail.com", "mamamiya");
    sleep(3);
    bee_logout();
    sleep(1);
	return 0;
}
