LDFLAGS += -L../../src
LDLIBS += -ldlbind -lelf -ldl
CFLAGS += -g -Wextra -I../../include

default: elfproto-simple

run: elfproto-simple
	gdb --eval-command "source gdb-script" ./elfproto-simple

clean:
	rm -f elfproto-simple
