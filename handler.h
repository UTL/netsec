#ifndef HNADLER_H
#define HNADLER_H

void init(char * sid, char * pw);

void setBeacon(char * newSid, unsigned char * newMac);

void setEap(unsigned char * nonce, unsigned char * count, unsigned char * smac, unsigned char * dmac);

#endif
