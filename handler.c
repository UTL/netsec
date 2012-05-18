#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

#define PWD_SIZE 63
#define TK_SIZE 128
#define NONCE_SIZE 32
#define COUNTER_SIZE 8
#define MAC_SIZE 6

//lo stato dell'handshake eap
#define EMPTY 0 //non ancora partito
#define ONE 1
#define TWO 2
#define THR 3
#define DONE 4


//parametri beacon
struct beacon_s{
	char				ssid[PWD_SIZE+1];
	unsigned char		apmac[MAC_SIZE];
};

//parametri eap
struct eap_st{
	unsigned char		anonce[NONCE_SIZE];
	unsigned char		snonce[NONCE_SIZE];
	unsigned char		apmac[MAC_SIZE];
	unsigned char		smac[MAC_SIZE];
	unsigned char		counter[COUNTER_SIZE];
	int 				status;
};

//parametri iniziali
struct sniffed_s{
	char				ssid[PWD_SIZE+1];
	char				pwd[PWD_SIZE+1];
};

//valori finali
struct sec_assoc{
	unsigned char		apmac[MAC_SIZE];
	unsigned char		smac[MAC_SIZE];
	unsigned char		tk[TK_SIZE];
};

struct eap_st *myEap = NULL;
struct beacon_s *myBeac;
struct sniffed_s *mySniff;
struct sec_assoc *mySecAss;

int eqCounter(unsigned char * count1, unsigned char * count2){
	 return !u_char_differ(count1, count2,COUNTER_SIZE);
	}

int eqMac(unsigned char * mac1, unsigned char * mac2){
	 return !u_char_differ(mac1, mac2,MAC_SIZE);
	}
	
int eqNonce(unsigned char * n1, unsigned char * n2){
	 return !u_char_differ(n1, n2,NONCE_SIZE);
	}

void init(){
	myEap = malloc(sizeof(struct eap_st));
	myEap->status = EMPTY;
	myBeac = malloc(sizeof(struct beacon_s));
	mySniff = malloc(sizeof(struct sniffed_s));
	mySecAss = malloc(sizeof(struct sec_assoc));
	
	}


//NB settare status a EMPTY
void setEap(unsigned char * nonce, unsigned char * count, unsigned char * smac, unsigned char * dmac){
	myEap->status;
		if(myEap->status == EMPTY && isNull(myEap->counter, COUNTER_SIZE)){ //sbagliato isnull, bisogna prima fare un memset a '\0'
			memcpy(myEap->counter, count, COUNTER_SIZE);
			memcpy(myEap->apmac, dmac, MAC_SIZE);
			memcpy(myEap->smac, smac, MAC_SIZE);
			memcpy(myEap->anonce, nonce, NONCE_SIZE);
			myEap->status = ONE;
			}
		else if(myEap->status == ONE && eqCounter(myEap->counter, count) && eqMac(myEap->smac, dmac) && eqMac(myEap->apmac, smac)){
			memcpy(myEap->snonce, nonce, NONCE_SIZE);
			myEap->status = TWO;
			}
		else if(myEap->status == TWO && (myEap->counter)[COUNTER_SIZE-1]+1 == count[COUNTER_SIZE-1] && eqMac(myEap->apmac, smac) && eqMac(myEap->smac, dmac) && eqNonce(nonce, myEap->anonce)){
			memcpy(myEap->counter, count, COUNTER_SIZE);
			myEap->status = THR;
			}
		else if(myEap->status == THR && eqMac(myEap->smac, dmac) && eqMac(myEap->apmac, smac) && isNull(count, COUNTER_SIZE)){
			myEap->status = DONE;
			}
		
	}
	
int main() {
	
	}
