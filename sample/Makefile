CFLAGS= -I../
LDFLAGS= ../libbee.a

.PHONY: all test1
all: test1

test1: test1.o
	$(CC) -o test1.exe test1.o $(CFLAGS) $(LDFLAGS)

clean:
	rm *.o  test1.exe -rf
