BEE lightweight P2P library for devcie and app
============================================
Brief
============================================
Bee library is a lite real-time message transfer system library.
It can embedded in the SoC system or Android / iOS system.






============================================
Application
============================================
===
HomeAutomation
Message Deliver
Deivce Management
Sensors
...


     JNI             MQTT   Network          Network  MQTT            function
app <--->   bee-lib <--->   .......   Cloud  ....... <--->   bee-lib  <--->   device-daemon

============================================
Preliminary:
============================================

User ID
User:
User can regiester a Service Manager account by using
1. Email
2. Unique User Name
3. Phone number

Password

the access password for this account

UID

system assigned a unique id for this account.
NOTICE: this is important when use connect / disconnect and send API


============================================
For APP
============================================

Library behavior map to Android Activity Lifecycle

Method 1: create pthread in library

    onCreate: -> bee_init

    onStart -> bee_user_login_x

    onResume -> bee_resume

    onDestroy -> bee_destroy


Method 2: no thread mode

    onCreate: -> bee_init_without_thread

    onStart: -> bee_user_login_x

    onResume -> bee_loop_forever / bee_resume

    onDestroy -> bee_destroy

============================================
Login:
============================================

Step1. call bee_user_init or bee_dev_init setup library

Step2. register status callback by bee_reg_status_cb

Step3. set user info for local access bee_set_user_info

Step4. login system by bee_user_login_x


============================================
Online / Offline Mode:
============================================

Pure Offline Mode:

    bee_user_init(xxxx);
    bee_set_service("xxxxxxx", "xxxxxxxxxxx");
    bee_reg_status_cb(status_cb);
    bee_reg_receiver_cb(conn_cb);
    bee_reg_message_cb(cmd_callback);
    bee_set_user_info("f835dd000022","gemtek2014", "600000751");
    bee_offline();


Pure Online Mode:

    bee_user_init(NULL);
    bee_set_service("HA-45058956", "0744424235");
    bee_reg_status_cb(status_cb);
    bee_user_login_id_pw("kaija.chang@gmail.com", "mamamiya");
    bee_reg_sender_cb(connector_callback);

Recommend Mode:

    bee_user_init(NULL);
    bee_set_service("HA-45058956", "0744424235");
    bee_reg_status_cb(status_cb);
    bee_set_user_info("f835dd000022","gemtek2014", "600000751");
    bee_user_login_id_pw("kaija.chang@gmail.com", "mamamiya");
    bee_reg_sender_cb(connector_callback);


============================================
Connect/Send data/ Disconnect:
============================================
Connect Example:
    bee_reg_sender_cb(connector_callback);
    bee_connect(xxxx);

    Step1. register a sender callback.
    Step2. call bee_connect
        xxxx could be the remote User Name(Device's MAC address/User's Email/User Name/Phone  read from SSDP neighbor list)

    Step3. your callback (connector_callback) will return the connection result



Send data Example:

    bee_send_data("600000751", -1 , tmp, 64000, SM_MSG_TYPE_RT);

    Step1. the sender callback will return the type of client (Local/ Remote)
        if local mode, it will return local connection id (cid). if remote side, it will return remote user id.

    Step2. call bee_send_data with remote id or cid and the data with length

