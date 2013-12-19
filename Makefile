
LIB_OBJS=bee.o

CFLAGS= -fPIC
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
	rm *.o *.a *.so -rf
	$(MAKE) -C sample clean
