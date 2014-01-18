.PHONY: openssl mosquitto bee
all: openssl mosquitto bee

openssl:
	cd openssl;./config
	$(MAKE) -C openssl

mosquitto:
	$(MAKE) -C mosquitto

bee:
	$(MAKE) -C bee

clean:
	$(MAKE) -C openssl clean
	$(MAKE) -C mosquitto clean
	$(MAKE) -C bee clean
