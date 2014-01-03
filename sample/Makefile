CFLAGS= -I../include -Wall
LDFLAGS= ../lib/libbee.a ../../mosquitto/lib/libmosquitto.a -lssl -lpthread

.PHONY: all test1 test2 test_api
all: test1 test2 test_api sensor

test1: test1.o
	$(CC) -o test1.exe test1.o $(CFLAGS) $(LDFLAGS)
test2: test2.o
	$(CC) -o test2.exe test2.o $(CFLAGS) $(LDFLAGS)
test_api: test_api.o
	$(CC) -o test_api.exe test_api.o $(CFLAGS) $(LDFLAGS)

sensor: sensor.o
	$(CC) -o sensor.exe sensor.o $(CFLAGS) $(LDFLAGS)

clean:
	rm *.o  test1.exe -rf
