.PHONY: default all clean test

default: all

all:
	$(MAKE) -C src
	$(MAKE) -C lib

clean:
	$(MAKE) -C src clean
	$(MAKE) -C lib clean

test:
	$(MAKE) -C test
