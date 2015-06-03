LDFLAGS += -L../../src
LDLIBS += -ldlbind -lelf -ldl
CFLAGS += -g -Wextra -I../../src

default: elfproto-simple

run: elfproto-simple
	gdb --eval-command "source gdb-script" ./elfproto-simple

clean:
	rm -f elfproto-simple
