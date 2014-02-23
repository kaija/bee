LIB_OBJS=bee.o
LIB_OBJS+= utils.o
LIB_OBJS+= sm_api.o

LIB_OBJS+= third_party/simclist.o
LIB_OBJS+= third_party/lssdp.o
LIB_OBJS+= third_party/parson.o
LIB_OBJS+= third_party/http.o
LIB_OBJS+= third_party/log.o

VERFILE=VERSION
ifneq ("$(wildcard $(VERFILE))","")
VERSION=$(shell cat VERSION)
CFLAGS+= -DBEE_VERSION="\"${VERSION}\""
else
CFLAGS+= -DBEE_VERSION="\"1\""
endif

CFLAGS+= -DBEE_LIB_VERION="2"

CFLAGS+= -g -fPIC -Wall -I./include -I../mosquitto/lib
CFLAGS+= -DHAVE_OPENSSL

SHARED_LIB=lib/libbee.so
STATIC_LIB=lib/libbee.a

.PHONY: shared static sample

all: prepare shared static sample

prepare:
	mkdir -p lib
shared: $(LIB_OBJS)
	$(CC) -shared -o $(SHARED_LIB) $(LIB_OBJS) $(CFLAGS)
static: $(LIB_OBJS)
	$(AR) rcs $(STATIC_LIB) $(LIB_OBJS)

sample:
	$(MAKE) -C sample


clean:
	rm -rf *.o lib/*.a lib/*.so third_party/*.o
	$(MAKE) -C sample clean
