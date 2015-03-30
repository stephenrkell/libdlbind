CC ?= gcc

LDFLAGS += -L`pwd` -Wl,-R`pwd` 
LDLIBS += -ldl -lelf
CFLAGS += -std=c11 -g -fPIC -Wextra #-DHAVE_ELF_SETSHSTRNDX 
CXXFLAGS += -std=gnu++14 -fpermissive

default: libld.a #test

libld.so: libld.o
	$(CC) $(CFLAGS) -shared -o "$@" "$<"

libld.a: libld.o symhash.o elfproto.o
	ar r "$@" $^ 

# Use the static version of libld for now, so we can ltrace -lelf
test: test.c libld.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o "$@" "$<" libld.a $(LDLIBS) #/usr/lib/libelf.so.0.8.13

make clean:
	rm -f *.o test libld.so libld.a
