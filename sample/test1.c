#include <stdio.h>
#include "bee.h"
int main()
{
    bee_dev_init();
    bee_dev_login_id_pw("f835dd000003", "gemtek");
    for(;;){
        sleep(1);
    }
	return 0;
}
