#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#define member_size(type, member) sizeof(((type *)0)->member)

FILE *fp;
int n_pacc;
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
	u_char other[13];
	}__attribute__ (( packed ));

struct eapol{
	struct in_eapol params;
	u_char nonce[32];
	}__attribute__ (( packed ));

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
 
void printhex(unsigned char * toPrint, int length){
	int k;
	for (k = 0;  k < length;  k++) 
		printf("%02x ", toPrint[k]);
	
	printf("\n");
	}
 
int main() {
	
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
 
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	//ether_type = ntohs(eptr->ether_type);
	
	struct ieee80211_radiotap_header *rh =(struct ieee80211_radiotap_header *)packet;

	struct mgmt_header_t *mac_header = (struct mgmt_header_t *) (packet+rh->it_len);
	
	
	if(n_pacc == 59 || n_pacc == 60){
		u_char * nonce = (u_char *) (packet +rh->it_len+ sizeof(struct mgmt_header_t)+ sizeof(struct llc) + sizeof(struct in_eapol)); //+ member_size(eapol,it_type) + member_size(eapol,it_len) + member_size(eapol,other));
		int i;
		printf("\nSperiamo nonce: \n");
		for(i=0; i<32;i++)
			printf("%.2x:", nonce[i]);
		printf("\n");
	}
	
	//u_int8_t buffer [200] = (u_int8_t *)(packet+rh->it_len);
		
	
	fprintf(fp, "PACCHETTO NUMERO : %d\n", n_pacc); 
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
