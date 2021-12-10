# HACK
include libsystrap/contrib/config.mk

CFLAGS += -g

vpath %.c libsystrap/contrib

example example.o: CFLAGS += -I../include -Ilibsystrap/include -I$(LIBRUNT_DIR)/include
example: LDFLAGS += -fno-lto -L../lib -Llibsystrap/lib -L$(LIBRUNT_DIR)/lib \
 -Wl,--defsym,__wrap___runt_files_metadata_by_addr=__runt_files_metadata_by_addr \
 -Wl,--defsym,__wrap___runt_files_notify_load=__runt_files_notify_load \
 -Wl,--defsym,__private_malloc=malloc -Wl,--defsym,__private_free=free \
 -Wl,--defsym,__private_realloc=realloc
example: LDLIBS += -ldlbind -lsystrap -Wl,--push-state -Wl,-static -lrunt -Wl,--pop-state -ldl

example: dlmalloc.o private-strdup.o

.PHONY: default
default: example
