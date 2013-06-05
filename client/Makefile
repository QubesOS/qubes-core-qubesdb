CFLAGS += -I../include -g -Wall -Werror -pie -fPIC

LIBDIR=/usr/lib64

all: libqubesdb.so

install: all
	install -d $(DESTDIR)$(LIBDIR)
	install libqubesdb.so* $(DESTDIR)$(LIBDIR)/

libqubesdb.so: qdb-client.o
	$(CC) $(LDFLAGS) -shared -o $@ $^ $(APPEND_LDFLAGS)

clean:
	rm -f libqubesdb.so *.o
