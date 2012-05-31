# richiede libssl-dev

OUTFILE=cclient
LIBS=openssl
INCDIR=-I/usr/include
PRF=prf_ptk.c
SNIFFER=sniffer.c
UTILS=utils.c
HANDL=handler.c
TINY_C=client.c
TINY_O=tinyClient

all:
	gcc-4.4 $(INCDIR) `pkg-config --libs $(LIBS)` -lpcap $(PRF) $(SNIFFER) $(UTILS) $(HANDL)  -o $(OUTFILE)

debug:
	gcc-4.4 $(INCDIR) -g `pkg-config --libs $(LIBS)` -lpcap $(PRF) $(SNIFFER) $(UTILS) $(HANDL)  -o $(OUTFILE)

tiny:
	gcc-4.4 $(TINY_C) -o $(TINY_O)

clean:
	find -iname "*.o" -type f -print0 | xargs -0 rm -f
	rm -f $(OUTFILE) $(TINY_O)

