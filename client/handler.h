#ifndef HNADLER_H
#define HNADLER_H
#include <pcap.h>
void init(char * sid, char * pw);

void setBeacon(char * newSid, unsigned char * newMac, int socketDescr);

void setEap(unsigned char * nonce, unsigned char * count, unsigned char * smac, unsigned char * dmac, int socketDescr);

void setData(struct pcap_pkthdr* pkthdr, const unsigned char* packet, int socketDescriptor);

#endif
