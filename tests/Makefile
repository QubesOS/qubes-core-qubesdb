CFLAGS += -D_GNU_SOURCE -UNDEBUG -I../fuzz -I../include -I../daemon -g -Wall -Werror

SOURCES = test_vchan_backpressure.c ../daemon/db-cmds.c ../daemon/db-core.c ../daemon/buffer.c
HEADERS = ../daemon/qubesdb_internal.h ../daemon/buffer.h ../include/qubesdb.h ../fuzz/libvchan.h

test: test_vchan_backpressure
	./test_vchan_backpressure

test_vchan_backpressure: $(SOURCES) $(HEADERS) ../daemon/db-daemon.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SOURCES)

clean:
	rm -f test_vchan_backpressure db-daemon.o

.PHONY: test clean
