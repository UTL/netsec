# richiede libssl-dev

OUTFILE=out
LIBS=openssl
INCDIR=-I/usr/include
PRF=prf_ptk.c
SNIFFER=sniffer.c
OUT_SNIFFER=sniffer
UTILS=utils.c
ARRAY=dyn_array.c
HANDL=handler.c

all:
	gcc $(INCDIR) -g `pkg-config --libs $(LIBS)` -lpcap $(PRF) $(SNIFFER) $(UTILS) $(HANDL) -o $(OUTFILE)

prf:
	gcc $(INCDIR) `pkg-config --libs $(LIBS)` $(PRF) $(UTILS) -o $(OUTFILE)

sniffer:
	gcc $(INCDIR) $(SNIFFER) $(UTILS) -o $(OUT_SNIFFER) -lpcap

handler:
	gcc $(INCDIR) `pkg-config --libs $(LIBS)` -lpcap $(HANDL) $(UTILS) -o $(OUTFILE)

clean:
	find -iname "*.o" -type f -print0 | xargs -0 rm -f
	rm -f $(OUTFILE)
	rm -f $(OUT_SNIFFER)

