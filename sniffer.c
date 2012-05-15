#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define EAP_TO_COUNTER 9
#define member_size(type, member) sizeof(((type *)0)->member)
u_char * BROADCAST;
u_char * EAP;

FILE *fp;
int n_pacc;

struct challenge_data{
	u_char		anonce[32];
	u_char		snonce[32];
	u_char		dmac[6];
	u_char		smac[6];
	u_char		counter[8];
	}
	
struct challenge_data chall;

struct mgmt_header_t {
    u_int16_t    fc;          /* 2 bytes */
    u_int16_t    duration;    /* 2 bytes */
    u_int8_t     da[6];       /* 6 bytes */
    u_int8_t     sa[6];       /* 6 bytes */
    u_int8_t     bssid[6];    /* 6 bytes */
    u_int16_t    seq_ctrl;    /* 2 bytes */
} __attribute__ (( packed ));

struct ieee80211_radiotap_header{
    u_int8_t it_version;
    u_int8_t it_pad;
    u_int16_t it_len;
    u_int32_t it_present;
}__attribute__ (( packed ));

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
	u_char nonce[32];
	}__attribute__ (( packed ));



void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int chartoint(char car){
	int intero = 0;
	intero = car - '0';
	if(intero < 10 && intero > -1)
		return intero;
	else
		return car - 'a' + 10; //caratteri mappati diversamente

}

char * extochar(char * in, int inLen){
	int i,k;
	int resInt[inLen/2];
	char * resChar=malloc(inLen/2);

	k=0;
	for(i=0; i<inLen/2; i=i++){
		resInt[k]=chartoint(in[i*2])<<4;
		resInt[k]+=chartoint(in[(i*2)+1]);
		k++;
	}

	for(k=0; k<inLen/2;k++){
		resChar[k]=(char)resInt[k];
	}
	return resChar;
} 

int u_char_differ(unsigned char *a, unsigned char *b, int size) {
	while(size -- > 0) {
		if ( *a != *b ) 
			return 1;
		a++; b++;
	}
	return 0;
}

 
int main() {
	char ff[] = "ffffffffffff";
	BROADCAST = extochar(ff, strlen(ff));
	
	char eap[] = "aaaa03000000888e";
	EAP = extochar(eap, strlen(eap));
	
	n_pacc = 1;
	pcap_t *descr;
	char errbuf[PCAP_ERRBUF_SIZE];

	// open capture file for offline processing
	descr = pcap_open_offline("./wpa/cap/handshake_angie.cap", errbuf);
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

u_char * getCounter(const u_char* packet, struct ieee80211_radiotap_header *rh){
	return (u_char *) (packet +rh->it_len+ sizeof(struct mgmt_header_t)+ sizeof(struct llc) +EAP_TO_COUNTER);
	}

void eap_mgmt(const u_char* packet, struct ieee80211_radiotap_header *rh, struct mgmt_header_t *mac_header){
		
		if(chall->counter == NULL)
			chall->counter = getCounter(packet, rh);
		else if(!u_char_differ(chall->counter, getCounter(packet, rh) , 8)){
			u_char * llcc = (u_char *) (packet +rh->it_len+ sizeof(struct mgmt_header_t));
			printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", llcc[0],llcc[1],llcc[2],llcc[3],llcc[4],llcc[5]);
			printf("PACCHETTO NUMERO : %d E' EAP\n", n_pacc);

			u_char * nonce = (u_char *) (packet +rh->it_len+ sizeof(struct mgmt_header_t)+ sizeof(struct llc) + sizeof(struct in_eapol)); //+ member_size(eapol,it_type) + member_size(eapol,it_len) + member_size(eapol,other));
			int i;
			printf("\nSperiamo nonce: \n");
			for(i=0; i<32;i++)
				printf("%.2x:", nonce[i]);
			printf("\n");
		}
	}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	//ether_type = ntohs(eptr->ether_type);
	
	struct ieee80211_radiotap_header *rh =(struct ieee80211_radiotap_header *)packet;

	struct mgmt_header_t *mac_header = (struct mgmt_header_t *) (packet+rh->it_len);

	fprintf(fp, "PACCHETTO NUMERO : %d, dimensione pacchetto: %d \n", n_pacc, pkthdr->caplen); 
	
	
	if(pkthdr->caplen < 49) //questo controllo andrebbe fatto prima di prendere i dati dal pacchetto con gli struct
		fprintf(fp, "Pacchetto piccolo\n"); //scarto i pacchetti senza dati
	else if(!u_char_differ(mac_header->da, BROADCAST, 6))
		fprintf(fp, "Pacchetto broadcast\n"); //scarto i pacchetti broadcast
	else if(!u_char_differ((u_char *) (packet +rh->it_len+ sizeof(struct mgmt_header_t)), EAP, 8)){
		eap_mgmt(packet, rh, mac_header);
		}
n_pacc++;
	//if(mac_header->da[0] == (u_int8_t) 255 && mac_header->da[1] == (u_int8_t) 255 &&  mac_header->da[2] == (u_int8_t) 255 &&  mac_header->da[3] == (u_int8_t) 255 &&  mac_header->da[4] == (u_int8_t) 255 &&  mac_header->da[5]== (u_int8_t) 255)


	fprintf(fp, "MAC da: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", mac_header->da[0], mac_header->da[1], mac_header->da[2], mac_header->da[3], mac_header->da[4], mac_header->da[5]);
	fprintf(fp, "MAC sa  : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", mac_header->sa[0], mac_header->sa[1], mac_header->sa[2], mac_header->sa[3], mac_header->sa[4], mac_header->sa[5]);
	fprintf(fp, "MAC bssid  : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", mac_header->bssid[0], mac_header->bssid[1], mac_header->bssid[2], mac_header->bssid[3], mac_header->bssid[4], mac_header->bssid[5]);

	
	//ethernetHeader = (struct ether_header*)packet;
	
	//fprintf(fp, "pacchetto %d\n",ntohs(ethernetHeader->ether_type));
	
	//if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
		/*//printf("pacchetto ip\n");
		ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
		inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);
 
		if (ipHeader->ip_p == IPPROTO_TCP) {
			tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
			sourcePort = ntohs(tcpHeader->source);
			destPort = ntohs(tcpHeader->dest);
			data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
			dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));

		}*/
	//}

}
