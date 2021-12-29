OUTDIR = bin/$(ARCH)
CFLAGS += -I../include -std=c11 -fgnu89-inline -DUNICODE -D_UNICODE
LDFLAGS += -L$(OUTDIR) -lwindows-utils

all: $(OUTDIR) $(OUTDIR)/qubesdb-client.dll $(OUTDIR)/qubesdb-cmd.exe $(OUTDIR)/qubesdb-daemon.exe

$(OUTDIR):
	mkdir -p $@

$(OUTDIR)/qubesdb-client.dll: ../client/qdb-client.c
	$(CC) $^ $(CFLAGS) $(LDFLAGS) -lwindows-utils -DQUBESDBCLIENT_API -shared -DWIN32 -o $@

$(OUTDIR)/qubesdb-cmd.exe: $(OUTDIR)/qubesdb-client.dll ../client/qubesdb-cmd.c
	$(CC) ../client/qubesdb-cmd.c  $(CFLAGS) $(LDFLAGS) -lwindows-utils -lqubesdb-client -DWIN32 -UUNICODE -U_UNICODE -mconsole -o $@

$(OUTDIR)/qubesdb-daemon.exe: $(OUTDIR)/qubesdb-client.dll $(wildcard ../daemon/*.c)
	$(CC) $(filter %.c,$^) $(CFLAGS) $(LDFLAGS) -lwindows-utils -lqubesdb-client -lvchan -DWIN32 -UUNICODE -U_UNICODE -o $@
