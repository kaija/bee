CFLAGS= -I../include -Wall
LDFLAGS= ../lib/libbee.a ../../mosquitto/lib/libmosquitto.a -lssl -lpthread -lrt

.PHONY: all dev_connect user_connect test_api nothread user_nothread user_local android switch
all: dev_connect user_connect test_api sensor nothread user_nothread user_local android switch

dev_connect: dev_connect.o
	$(CC) -o dev_connect.exe dev_connect.o $(CFLAGS) $(LDFLAGS)

user_connect: user_connect.o
	$(CC) -o user_connect.exe user_connect.o $(CFLAGS) $(LDFLAGS)

test_api: test_api.o
	$(CC) -o test_api.exe test_api.o $(CFLAGS) $(LDFLAGS)

sensor: sensor.o
	$(CC) -o sensor.exe sensor.o $(CFLAGS) $(LDFLAGS)

nothread: nothread.o
	$(CC) -o nothread.exe nothread.o $(CFLAGS) $(LDFLAGS)

user_nothread: user_nothread.o
	$(CC) -o user_nothread.exe user_nothread.o $(CFLAGS) $(LDFLAGS)

user_local: user_local.o
	$(CC) -o user_local.exe user_local.o $(CFLAGS) $(LDFLAGS)

android: android.o
	$(CC) -o android.exe android.o $(CFLAGS) $(LDFLAGS)

switch: switch.o
	$(CC) -o switch.exe switch.o $(CFLAGS) $(LDFLAGS)


clean:
	rm *.o  *.exe -rf
