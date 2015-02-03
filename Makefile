CC ?= gcc

LDFLAGS += -L`pwd` -Wl,-R`pwd` 
LDLIBS += -ldl -lelf
CFLAGS += -g -fPIC -Wextra #-DHAVE_ELF_SETSHSTRNDX 

default: libld.so libld.a test

libld.o: libld.c
	$(CC) $(CFLAGS) -c -o "$@" "$<"

libld.so: libld.o
	$(CC) $(CFLAGS) -shared -o "$@" "$<"

libld.a: libld.o
	ar r "$@" $^ 

# Use the static version of libld for now, so we can ltrace -lelf
test: test.c libld.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o "$@" "$<" libld.a $(LDLIBS) #/usr/lib/libelf.so.0.8.13

make clean:
	rm -f *.o test libld.so libld.a
