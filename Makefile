.PHONY: default all clean test

default: all

all:
	$(MAKE) -C src

clean:
	$(MAKE) -C src clean

test:
	$(MAKE) -C test
