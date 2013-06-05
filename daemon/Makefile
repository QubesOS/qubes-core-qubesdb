
CFLAGS += -I../include -I. -g -Wall -Werror -pie -fPIC
CFLAGS += `pkg-config --cflags libsystemd-daemon`
CFLAGS += `pkg-config --cflags vchan-$(BACKEND_VMM)`

LDFLAGS += `pkg-config --libs libsystemd-daemon`
LDFLAGS += `pkg-config --libs vchan-$(BACKEND_VMM)`

SBINDIR = /usr/sbin

all: qubesdb-daemon

install:
	install -d $(DESTDIR)$(SBINDIR)
	install qubesdb-daemon $(DESTDIR)$(SBINDIR)/

qubesdb-daemon: db-cmds.o db-daemon.o db-core.o
	$(CC) $(LDFLAGS) -o $@ $^ $(APPEND_LDFLAGS)

