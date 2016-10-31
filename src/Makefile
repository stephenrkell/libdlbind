CC ?= gcc

LDFLAGS += -L`pwd` -Wl,-R`pwd` 
LDLIBS += -ldl -lelf
CFLAGS += -std=c11 -g -fPIC -Wextra #-DHAVE_ELF_SETSHSTRNDX 
CFLAGS += -I$(LIBALLOCS_BASE)/include
CFLAGS += -I../include
CXXFLAGS += -std=gnu++14 -fpermissive
CXXFLAGS += -g3

CC_DEPS := $(patsubst %.cc,.%.d,$(wildcard *.cc))
C_DEPS := $(patsubst %.c,.%.d,$(wildcard *.c))

DEPS := $(CC_DEPS) $(C_DEPS)

default: libdlbind.a #test

.%.d: %.c
	$(CC) $(CFLAGS) -c -MM "$<" > "$@" || rm -f "$@"
.%.d: %.cc
	$(CXX) $(CXXFLAGS) -c -MM "$<" > "$@" || rm -f "$@"

-include $(DEPS)

libdlbind.so: libdlbind.o
	$(CC) $(CFLAGS) -shared -o "$@" "$<"

libdlbind.a: libdlbind.o symhash.o elfproto.o
	ar r "$@" $^ 

# Use the static version of libld for now, so we can ltrace -lelf
test: test.c libdlbind.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o "$@" "$<" libdlbind.a $(LDLIBS) #/usr/lib/libelf.so.0.8.13

make clean:
	rm -f *.o test libdlbind.so libdlbind.a
