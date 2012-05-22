#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include "utils.h"
#include "handler.h"
#include "prf_ptk.h"


#define PWD_SIZE 63
#define TK_SIZE 16
#define NONCE_SIZE 32
#define COUNTER_SIZE 8
#define MAC_SIZE 6
#define AAD_SIZE 22

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
	unsigned char * tk;
};

struct eap_st *myEap = NULL;
struct beacon_s *myBeac;
struct sniffed_s *mySniff;
struct sec_assoc *mySecAss;

int eqCounter(unsigned char * count1, unsigned char * count2){
	 return !u_char_differ(count1, count2,COUNTER_SIZE);
	}

int eqMac(unsigned char * mac1, unsigned char * mac2){
	return !u_char_differ(mac1, mac2, MAC_SIZE);
	}
	
int eqNonce(unsigned char * n1, unsigned char * n2){
	 return !u_char_differ(n1, n2,NONCE_SIZE);
	}

void init(char * sid, char * pw){
	myBeac = malloc(sizeof(struct beacon_s));
	mySniff = malloc(sizeof(struct sniffed_s));
	
	strcpy(myBeac->ssid,"");
	
	strcpy(mySniff->ssid,"Sitecom");
	strcpy(mySniff->pwd, "angelatramontano");

	}

int ready(){
	return strlen(myBeac->ssid) && myEap->status==DONE &&  eqMac(myBeac->apmac, myEap->smac);//se abbiamo almeno un beacon, un handshake eap e gli apmac coincidono possiamo cominciare a decriptare
	}

void setSecAss(){
	if(mySecAss == NULL)
		mySecAss = malloc(sizeof(struct sec_assoc));
	mySecAss->tk = calc_tk(mySniff->pwd, mySniff->ssid, myEap->apmac, myEap->smac, myEap->anonce, myEap->snonce);
	memcpy(mySecAss->apmac, myEap->apmac, MAC_SIZE);
	memcpy(mySecAss->smac, myEap->smac, MAC_SIZE);
	}
	
	
struct sec_assoc * getSecAss(unsigned char * smac, unsigned char * dmac){
	if(mySecAss!=NULL)
		if ((eqMac(mySecAss->apmac, dmac) && eqMac(mySecAss->smac, smac)) || (eqMac(mySecAss->smac, dmac) && eqMac(mySecAss->apmac, smac)))
			return mySecAss;
	return NULL;
	}
	
struct eap_st * macsPresent(unsigned char * smac, unsigned char * dmac){
	if(myEap!=NULL)
		if ((eqMac(myEap->apmac, dmac) && eqMac(myEap->smac, smac)) || (eqMac(myEap->smac, dmac) && eqMac(myEap->apmac, smac)))
			return myEap;
	return NULL;
	}

void createNew(unsigned char * nonce, unsigned char * count, unsigned char * smac, unsigned char * dmac){
	if(myEap==NULL)
		myEap = (struct eap_st *)(malloc(sizeof(struct eap_st)));
	myEap->status = EMPTY;
	memcpy(myEap->counter, count, COUNTER_SIZE);
	memcpy(myEap->apmac, dmac, MAC_SIZE);
	memcpy(myEap->smac, smac, MAC_SIZE);
	memcpy(myEap->anonce, nonce, NONCE_SIZE);
	myEap->status = ONE;
	}

void resetHandshake(unsigned char * nonce, unsigned char * count, unsigned char * smac, unsigned char * dmac, struct eap_st * toReset){
	createNew(nonce, count, smac, dmac);
	}

int increasedCounter(unsigned char c1[COUNTER_SIZE],unsigned char c2[COUNTER_SIZE]){
	return eqCounter(u_char_increase(c1,COUNTER_SIZE),c2);
	}

/*
 * 
 * if(myEap->status == EMPTY && isNull(myEap->counter, COUNTER_SIZE)){ //sbagliato isnull, bisogna prima fare un memset a '\0'
			
			}
 * 
 */

void setEap(unsigned char * nonce, unsigned char * count, unsigned char * smac, unsigned char * dmac){
	struct eap_st * anEap= NULL;
	if((anEap = macsPresent(smac, dmac))!= NULL){
		if(eqCounter(anEap->counter, count)){//secondo run eapol A <-- B
			if(anEap->status == ONE && eqMac(anEap->smac, dmac) && eqMac(anEap->apmac, smac)){
				memcpy(anEap->snonce, nonce, NONCE_SIZE);
				anEap->status = TWO;
				}
			}
		else if(increasedCounter(anEap->counter, count)){//terzo run eapol A --> B
			if(anEap->status == TWO && eqMac(anEap->apmac, dmac) && eqMac(anEap->smac, smac) && eqNonce(nonce, anEap->anonce)){
				//memcpy(anEap->counter, count, COUNTER_SIZE);
				anEap->status = THR;
				}
			else if(anEap->status == THR && eqMac(anEap->smac, dmac) && eqMac(anEap->apmac, smac)){//quarto run eapol A <-- B
				anEap->status = DONE;
				}
			}
		else
			resetHandshake(nonce, count, smac, dmac, anEap); // nuovo handshake resetto
			}
	else{//primo run eapol A --> B
		createNew(nonce, count, smac, dmac);
		}
	if(ready())
		setSecAss();
	}
	
void setBeacon(char * newSid, unsigned char * newMac){
	if(!strcmp(mySniff->ssid, newSid) && !strlen(myBeac->ssid))
		strcpy(myBeac->ssid, newSid);
		memcpy(myBeac->apmac, newMac, MAC_SIZE);
	}

void decrypt(unsigned char *aad,unsigned char *nonce,unsigned char *data, int data_length, unsigned char * tk){
	
	int i;
	
	printf("\"{\\\"aad\\\":\\\"0x");
	for(i=0; i<AAD_SIZE;i++)
		printf("%.2x",aad[i]);
	
	printf("\\\",\\\"nonce\\\":\\\"0x");
	for(i=0; i<NONCE_SIZE;i++)
		printf("%.2x",nonce[i]);
	
	printf("\\\",\\\"data\\\":\\\"0x");
	for(i=0; i<data_length;i++)
		printf("%.2x",data[i]);
	
	printf("\\\",\\\"tk\\\":\\\"0x");
	for(i=0; i<TK_SIZE;i++)
		printf("%.2x",tk[i]);
	
	printf("\\\"}\"\n");
	}

void setData(struct pcap_pkthdr* pkthdr, const unsigned char* packet){
	struct ieee80211_radiotap_header *rh =(struct ieee80211_radiotap_header *)packet;

	struct mgmt_header_t *mac_header = (struct mgmt_header_t *) (packet+rh->it_len);
	
	unsigned char * a2 = mac_header->sa;
	
	unsigned char * tempIv = (unsigned char *)(packet+rh->it_len+sizeof(struct mgmt_header_t));
	
	unsigned char iv[6];
	iv[0]=tempIv[7];
	iv[1]=tempIv[6];
	iv[2]=tempIv[5];
	iv[3]=tempIv[4];
	iv[4]=tempIv[1];
	iv[5]=tempIv[0];
	
	unsigned char nonce[13];
	nonce[0]= 0x00;
	memcpy(&nonce[1], a2, MAC_SIZE);
	memcpy(&nonce[7],&iv[0], 6);
	
	unsigned char fc[2];
	memcpy(&fc, &mac_header->fc,2);
	
	fc[0] &= 0b10001111;
	fc[1] &= 0b11000111;
	
	fc[1] |= 0b01000000;
	
	unsigned char sc[2];
	memcpy(sc, &mac_header->bssid + sizeof(unsigned char),2);
	sc[0] &= 0b00001111;
	sc[1] &= 0b00000000;
	
	unsigned char aad[AAD_SIZE];
	memcpy(&aad[0], &fc[0],2);
	memcpy(&aad[2], &mac_header->da, MAC_SIZE);
	memcpy(&aad[8], &mac_header->sa, MAC_SIZE);
	memcpy(&aad[14], &mac_header->bssid, MAC_SIZE);
	memcpy(&aad[20], &sc, 2);
	
	unsigned char * data = (unsigned char *)(packet+rh->it_len + sizeof(struct mgmt_header_t) + sizeof(char)*8);//char*8 è la lunghezza dell'iv
	
	int data_length = pkthdr->caplen - 56;
	
	struct sec_assoc * secAss;
	
	if((secAss = getSecAss(mac_header->da, mac_header->sa)) != NULL)
		decrypt(aad, nonce, data, data_length, secAss->tk);
	
	//costruire il nonce:
	// 0x00 concatenato, 2^ indirizzo mac, concatenato (filippando l'ordine dei bytes(l'inizialization vector prendendo primi 2 bytes poi ne salto 2 poi ne prendo 4))
	}




























