
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
else
VERSION=$(shell git log -1 --pretty="%H")
endif

CFLAGS= -fPIC -Wall -I./include
CFLAGS+= -DHAVE_OPENSSL
CFLAGS+= -DWITH_THREADING
CFLAGS+= -DBEE_VERSION="\"${VERSION}\""
LDFLAGS=
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
	rm *.o lib/*.a lib/*.so third_party/*.o -rf
	$(MAKE) -C sample clean
