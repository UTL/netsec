# richiede libssl-dev

OUTFILE=out
LIBS=openssl
INCDIR=-I/usr/include
HMAC=prova_hmac.c
K_EXPANSION=prova_key_expansion.c
HMAC2=prova_hmac_bis.c
PRF=prf_ptk.c
SNIFFER=sniffer.c
OUT_SNIFFER=sniffer

all:	hmac

hmac:
	gcc $(INCDIR) `pkg-config --libs $(LIBS)` $(HMAC) -o $(OUTFILE)
	
hmac2:
	gcc $(INCDIR) `pkg-config --libs $(LIBS)` $(HMAC2) -o $(OUTFILE)	

kexp:
	gcc $(INCDIR) `pkg-config --libs $(LIBS)` $(K_EXPANSION) -o $(OUTFILE)

prf:
	gcc $(INCDIR) `pkg-config --libs $(LIBS)` $(PRF) -o $(OUTFILE)

sniffer:
	gcc $(INCDIR) $(SNIFFER) -o $(OUT_SNIFFER) -lpcap

clean:
	find -iname "*.o" -type f -print0 | xargs -0 rm -f
	rm -f $(OUTFILE)
	rm -f $(OUT_SNIFFER)

