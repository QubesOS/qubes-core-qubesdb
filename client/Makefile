CFLAGS += -I../include -g -Wall -Werror -pie
ifneq ($(OS),Windows_NT)
CFLAGS += -fPIC
else
CFLAGS += -DUNICODE -D_UNICODE
endif

LIBDIR=/usr/lib64
BINDIR=/usr/bin

all: libqubesdb qubesdb-cmd

install: all
	install -d $(DESTDIR)$(LIBDIR)
	install libqubesdb.so* $(DESTDIR)$(LIBDIR)/
	install -d $(DESTDIR)$(BINDIR)
	install qubesdb-cmd $(DESTDIR)$(BINDIR)/
	ln -s qubesdb-cmd $(DESTDIR)$(BINDIR)/qubesdb-read
	ln -s qubesdb-cmd $(DESTDIR)$(BINDIR)/qubesdb-write
	ln -s qubesdb-cmd $(DESTDIR)$(BINDIR)/qubesdb-rm
	ln -s qubesdb-cmd $(DESTDIR)$(BINDIR)/qubesdb-multiread
	ln -s qubesdb-cmd $(DESTDIR)$(BINDIR)/qubesdb-list
	ln -s qubesdb-cmd $(DESTDIR)$(BINDIR)/qubesdb-watch

.PHONY: libqubesdb
ifeq ($(OS),Windows_NT)
libqubesdb: libqubesdb.dll
else
libqubesdb: libqubesdb.so
endif

libqubesdb.so: qdb-client.o
	$(CC) $(LDFLAGS) -shared -o $@ $^ $(APPEND_LDFLAGS)

libqubesdb.dll: qdb-client.o
	$(CC) -shared -o $@ $^ -Wl,--output-def,libqubesdb.def,--out-implib,libqubesdb.dll.a

qubesdb-cmd: qubesdb-cmd.o libqubesdb.so
	$(CC) $(LDFLAGS) -o $@ $< $(APPEND_LDFLAGS) -L. -lqubesdb

clean:
	rm -f libqubesdb.so qubesdb-cmd *.o
