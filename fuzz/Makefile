CFLAGS += -g
CFLAGS += -I.
CFLAGS += -I../daemon
CFLAGS += -I../include
CFLAGS += -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1

all: db-daemon_fuzzer_seed_corpus.zip db-daemon_fuzzer

db-daemon_fuzzer: buffer.o db-cmds.o db-core.o db-daemon.o db-daemon_fuzzer.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIB_FUZZING_ENGINE)

db-daemon_fuzzer_seed_corpus.zip: seed-corpus/*
	zip -q -r $@ seed-corpus	

buffer.o: ../daemon/buffer.c
	$(CC) $(CFLAGS) -o $@ -c $^

db-cmds.o: ../daemon/db-cmds.c
	$(CC) $(CFLAGS) -o $@ -c $^

db-core.o: ../daemon/db-core.c
	$(CC) $(CFLAGS) -o $@ -c $^

db-daemon.o: ../daemon/db-daemon.c
	$(CC) $(CFLAGS) -o $@ -c $^

clean:
	rm -f *.o
	rm -f db-daemon_fuzzer
	rm -f db-daemon_fuzzer_seed_corpus.zip

