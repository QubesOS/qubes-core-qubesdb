CFLAGS += -D_GNU_SOURCE -UNDEBUG -I../fuzz -I../include -I../daemon -g -Wall -Werror

SOURCES = test_recursive_watch.c ../daemon/db-cmds.c ../daemon/db-core.c ../daemon/buffer.c
HEADERS = ../daemon/qubesdb_internal.h ../daemon/buffer.h ../include/qubesdb.h ../fuzz/libvchan.h

test: test_recursive_watch
	./test_recursive_watch

test_recursive_watch: $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SOURCES) $(LDLIBS)

clean:
	rm -f test_recursive_watch

.PHONY: test clean
