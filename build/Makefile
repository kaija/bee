.PHONY: openssl mosquitto bee
all: openssl mosquitto bee

openssl:
	cd openssl;./Configure darwin64-x86_64-cc
	$(MAKE) -C openssl

mosquitto:
	$(MAKE) -C mosquitto

bee:
	$(MAKE) -C bee

clean:
	$(MAKE) -C openssl clean
	$(MAKE) -C mosquitto clean
	$(MAKE) -C bee clean
