
LIB_OBJS=bee.o
LIB_OBJS+= utils.o
LIB_OBJS+= sm_api.o

LIB_OBJS+= third_party/simclist.o
LIB_OBJS+= third_party/lssdp.o
LIB_OBJS+= third_party/parson.o
LIB_OBJS+= third_party/http.o
LIB_OBJS+= third_party/log.o


CFLAGS= -fPIC -Wall -I./include -I../mosquitto/lib
CFLAGS+= -DHAVE_OPENSSL
LDFLAGS=
SHARED_LIB=libbee.so
STATIC_LIB=libbee.a

.PHONY: shared static sample

all: shared static sample

shared: $(LIB_OBJS)
	$(CC) -shared -o $(SHARED_LIB) $(LIB_OBJS) $(CFLAGS)
static: $(LIB_OBJS)
	$(AR) rcs $(STATIC_LIB) $(LIB_OBJS)

sample:
	$(MAKE) -C sample


clean:
	rm *.o *.a *.so third_party/*.o -rf
	$(MAKE) -C sample clean
