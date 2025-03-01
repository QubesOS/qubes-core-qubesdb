
CFLAGS += -I../include -I. -g -Wall -Werror -pie
EXEEXT =

SYSTEMD ?= 1

BACKEND_VMM ?= $(shell pkg-config --cflags vchan | sed 's/.*vchan-//')

ifneq ($(OS),Windows_NT)
CFLAGS += -fPIC -O2
CFLAGS += `pkg-config --cflags vchan`
ifeq ($(SYSTEMD),1)
CFLAGS += `pkg-config --cflags libsystemd || pkg-config --cflags libsystemd-daemon`
CFLAGS += -DHAVE_SYSTEMD
LIBS += `pkg-config --libs libsystemd || pkg-config --libs libsystemd-daemon`
endif
LIBS += `pkg-config --libs vchan`

else # Windows_NT
EXEEXT = .exe
CFLAGS += -I$(QUBES_INCLUDES)
CFLAGS += -DUNICODE -D_UNICODE
LIBS += -L$(QUBES_LIBS) -lvchan
endif
CFLAGS += -DBACKEND_VMM_$(BACKEND_VMM)

BINDIR ?= /usr/bin

all: qubesdb-daemon$(EXEEXT)

install:
	install -d $(DESTDIR)$(BINDIR)
	install qubesdb-daemon$(EXEEXT) $(DESTDIR)$(BINDIR)/

qubesdb-daemon$(EXEEXT): db-cmds.o db-daemon.o db-core.o buffer.o
	$(CC) $(LDFLAGS) -o $@ $^ $(APPEND_LDFLAGS) $(LIBS)

clean:
	rm -f *.o qubesdb-daemon$(EXEEXT)
