CFLAGS= -I../include
LDFLAGS= ../lib/libbee.a ../../mosquitto/lib/libmosquitto.a -lssl -lpthread

.PHONY: all test1 test2
all: test1 test2

test1: test1.o
	$(CC) -o test1.exe test1.o $(CFLAGS) $(LDFLAGS)
test2: test2.o
	$(CC) -o test2.exe test2.o $(CFLAGS) $(LDFLAGS)

clean:
	rm *.o  test1.exe -rf
