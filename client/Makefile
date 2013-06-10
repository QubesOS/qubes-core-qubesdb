CFLAGS += -I../include -g -Wall -Werror -pie -fPIC

LIBDIR=/usr/lib64
BINDIR=/usr/bin

all: libqubesdb.so qubesdb-cmd

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

libqubesdb.so: qdb-client.o
	$(CC) $(LDFLAGS) -shared -o $@ $^ $(APPEND_LDFLAGS)

qubesdb-cmd: qubesdb-cmd.o libqubesdb.so
	$(CC) $(LDFLAGS) -o $@ $< $(APPEND_LDFLAGS) -L. -lqubesdb

clean:
	rm -f libqubesdb.so qubesdb-cmd *.o
