#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "utils.h"
#include "prf_ptk.h"
#include "handler.h"

#define EAP_TO_COUNTER 9
#define member_size(type, member) sizeof(((type *)0)->member)

#define EAP_SIZE 8
#define BCAST_CONST "ffffffffffff"
#define EAP_CONST "aaaa03000000888e"
#define HA_CAP "/home/enrico/develop/netsec/wpa/cap/handshake_angie.cap"
#define MY_CAP "./maistrim.cap"
#define HOME_CAP "/home/enrico/develop/netsec/stream_home.cap"
#define UNI_CAP "./wpa/cap/uni.cap"
#define FC_BEACON 0x80
#define FC_DATA 0x08


u_char * BROADCAST;
u_char * EAP;

FILE *fp;
int n_pacc;





struct llc{
	u_char	data[8]; 
	}__attribute__ (( packed ));

struct in_eapol{
	u_char it_version;
	u_char it_type;
	u_char it_len[2];
	u_char other[5];
	u_char counter[8];
	}__attribute__ (( packed ));

struct eapol{
	struct in_eapol params;
	u_char nonce[NONCE_SIZE];
	}__attribute__ (( packed ));


void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);


void run_tv_check(){
	check_pbkdf2();
	check_prf();
	check_ptk();

	//testa tutto fino alla tk
	check_picci_stream();
	}
 
int main() {
	run_tv_check();
	
	
	//struct challenge_data chall2;
	BROADCAST = extochar(BCAST_CONST);
	
	EAP = extochar(EAP_CONST);
	
	//memset (chall.anonce,'\0',NONCE_SIZE);
	//memset (chall.snonce,'\0',NONCE_SIZE);
	
	init("Sitecom", "angelatramontano");
	
	//strcpy(chall.ssid,"Sitecom");
	//strcpy(chall.pwd, "angelatramontano");
	n_pacc = 1;
	pcap_t *descr;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	

	// open capture file for offline processing
	descr = pcap_open_offline(HA_CAP, errbuf);
	if (descr == NULL) {
		printf("errore durante pcap_open_live() : %s \n",errbuf);
		// "pcap_open_live() failed: " << errbuf << endl; TODO
		return 1;
	}
		
 	if(pcap_datalink(descr)==DLT_IEEE802_11_RADIO)
			printf("radiotape!");
			
 	fp = fopen("./output.txt", "w");
 
	// start packet processing loop, just like live capture
	if (pcap_loop(descr, 0, packetHandler, NULL) < 0) {
		printf("errore durante pcap_loop() : %s \n", pcap_geterr(descr));

		// TODO cout << "pcap_loop() failed: " << pcap_geterr(descr);
		return 1;
	}
	
	fclose(fp);
	
	printf("Fine cattura pacchetti\n");

	//TODO cout << "capture finished" << endl;
 
	return 0;
}


u_char * getCounter(const u_char* packet){
	struct ieee80211_radiotap_header *rh =(struct ieee80211_radiotap_header *)packet;
	return (u_char *) (packet +rh->it_len+ sizeof(struct mgmt_header_t)+ sizeof(struct llc) +EAP_TO_COUNTER);
	}

u_char * getNonce(const u_char* packet){
	struct ieee80211_radiotap_header *rh =(struct ieee80211_radiotap_header *)packet;
	return (u_char *) (packet +rh->it_len+ sizeof(struct mgmt_header_t)+ sizeof(struct llc) + sizeof(struct in_eapol));
	}

void eap_mgmt(const u_char* packet, struct ieee80211_radiotap_header *rh, struct mgmt_header_t *mac_header){
	//WARNING controllare la lunghezza dei pacchetti prima di fare getcounter e getnonce

	setEap(getNonce(packet), getCounter(packet), mac_header->sa, mac_header->da);
	/*int i;

			for(i=0; i<NONCE_SIZE;i++)
				printf("%.2x:", chall.snonce[i]);
			printf("\n");

		*/
	}


void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	//ether_type = ntohs(eptr->ether_type);

	
	struct ieee80211_radiotap_header *rh =(struct ieee80211_radiotap_header *)packet;


	struct mgmt_header_t *mac_header = (struct mgmt_header_t *) (packet+rh->it_len);

	
	fprintf(fp, "PACCHETTO NUMERO : %d, dimensione pacchetto: %d \n", n_pacc, pkthdr->caplen); 
	
	
	if(pkthdr->caplen < 49) //questo controllo andrebbe fatto prima di prendere i dati dal pacchetto con gli struct
		fprintf(fp, "Pacchetto piccolo\n"); //scarto i pacchetti senza dati
	else if(!u_char_differ(mac_header->da, BROADCAST, MAC_SIZE))
		fprintf(fp, "Pacchetto broadcast\n"); //scarto i pacchetti broadcast
	else if(!u_char_differ((u_char *) (packet +rh->it_len+ sizeof(struct mgmt_header_t)), EAP, EAP_SIZE)){
		//WARNING controllare la lunghezza dei pacchetti prima di fare getcounter e getnonce
		eap_mgmt(packet, rh, mac_header);
		}
		
	if((mac_header->fc & 0xff) == FC_BEACON){
		//lunghezza dello ssid
		u_int8_t * ssidLength = (u_char *) (packet +rh->it_len+ sizeof(struct mgmt_header_t) + sizeof(u_char)*13);

		//puntatore all'inizio del ssid
		u_char * ssid = (u_char *) (ssidLength + sizeof(u_char));
		
		u_char str_ssid[*ssidLength+1];
		memcpy(str_ssid, ssid, *ssidLength);
		
		str_ssid[*ssidLength]= '\0';
		
		setBeacon(str_ssid, mac_header->sa);
		//printf("ssid %s\n",str_ssid);
		}
	else if((mac_header->fc & 0xff) == FC_DATA){
		setData((struct pcap_pkthdr*)(pkthdr) , (unsigned char *)(packet));
	}
	n_pacc++;

}
