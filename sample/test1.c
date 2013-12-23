#include <stdio.h>
#include "bee.h"
int main()
{
    bee_dev_init();
    bee_set_service("HA-45058956", "0744424235");
    bee_dev_login_id_pw("f835dd000003", "gemtek");
    sleep(3);
    bee_send_message("600000125", 0, NULL, 0, 0);
    sleep(100);
	return 0;
}
