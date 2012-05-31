# richiede libssl-dev

OUTFILE=cclient
LIBS=openssl
INCDIR=-I/usr/include
PRF=prf_ptk.c
SNIFFER=sniffer.c
UTILS=utils.c
HANDL=handler.c

all:
	gcc-4.4 $(INCDIR) `pkg-config --libs $(LIBS)` -lpcap $(PRF) $(SNIFFER) $(UTILS) $(HANDL)  -o $(OUTFILE)

debug:
	gcc-4.4 $(INCDIR) -g `pkg-config --libs $(LIBS)` -lpcap $(PRF) $(SNIFFER) $(UTILS) $(HANDL)  -o $(OUTFILE)


clean:
	find -iname "*.o" -type f -print0 | xargs -0 rm -f
	rm -f $(OUTFILE)

