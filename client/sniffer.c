#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include "utils.h"
#include "prf_ptk.h"
#include "handler.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>


 
#define MAX 8192 /* in bytes, 8KB */

#define EAP_TO_COUNTER 9
#define member_size(type, member) sizeof(((type *)0)->member)

#define EAP_SIZE 8
#define BCAST_CONST "ffffffffffff"
#define EAP_CONST "aaaa03000000888e"
#define MY_CAP "./maistrim.cap"
#define HOME_CAP "/home/enrico/develop/netsec/stream_home.cap"
#define UNI_CAP "./wpa/cap/uni.cap"
#define FC_BEACON 0x80
#define FC_DATA 0x08
#define PORT 12345
#define HOST "127.0.0.1"

#define MSG_RADIOTAPE  "{\"command\":\"1\",\"msg\":\"Radiotape rilevato, inizio sniffing\"}\n"
#define  MSG_NO_RADIOTAPE "{\"command\":\"1\",\"msg\":\"Errore nessun radiotape rilevato\"}\n"
#define LOG_FILE "./log_client.txt"
u_char * BROADCAST;
u_char * EAP;

FILE *fp;
int n_pacc;

int sd;




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
	u_char nonce[EAP_NONCE_SIZE];
	}__attribute__ (( packed ));


void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);


void run_tv_check(){
	check_pbkdf2();
	check_prf();
	check_ptk();

	//testa tutto fino alla tk
	check_picci_stream();
	}
 

struct sockaddr_in init_socket() {
	//struttura che descrive l'indirizzo socket
	struct sockaddr_in server_addr;
	// indirizzo del serverchar buff[MAX];
	struct hostent* hp;
	hp = gethostbyname(HOST);
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(PORT);
	server_addr.sin_addr.s_addr = ((struct in_addr*) (hp->h_addr))->s_addr;
	return server_addr;
}

int file_exists(const char * filename){
	FILE * file;
    if ( file = fopen(filename, "r"))
    {
        fclose(file);
        return 1;
    }
    return 0;
}

//WARNING non controllo i permessi di scrittura nella directory
void createLog(char * path){
	FILE  * log = fopen(path, "w");
	printf("File di log non trovato creazione nuovo file di log\n");
	fprintf(log, "\n");
	fclose(log);
}

int main(int argc, char *argv[]) {
	if(!(argc==3 || argc ==4)){
		printf("Utilizzo:\n cclient \"ssid\" \"password\" [\"cap_path\"] \n1) Per la modalità live lanciare cclient come root seguito da ssid e password\n2) Per la modalità offline lanciare ");
		printf("cclient seguito dai parametri ssid, password e path del file cap\n");
		return 1;
	}

	run_tv_check();
	BROADCAST = extochar(BCAST_CONST);
	EAP = extochar(EAP_CONST);
	n_pacc = 1;
	
	//setto ssid e password
	init(argv[1], argv[2]);
	
	pcap_t *descr;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	//struttura che descrive l'indirizzo socket
	struct sockaddr_in server_addr = init_socket();
	// indirizzo del server
 
	//creazione del socket descriptor
	if((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		printf("Errore di creazione del socket\n");
		return 1;
	}

	//connessione al server
	if(connect(sd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
		printf("Errore di connessione al server\n Verificare di aver eseguito\n $../server/python pyserv.py\n");
		return 1;
	}


	if(argc==4){
		if( access( argv[3], R_OK ) != -1 )
			descr = pcap_open_offline(argv[3], errbuf);
		else{
			printf("Errore impossibile leggere il file cap %s\n", argv[3]);
			return 1;
		}
	}
	else //interfaccia, massima lunghezza snapshot, 1=promiscuo, timeout, buffer per errori
		descr = pcap_open_live("mon0",65535,1,2000,errbuf);

	if (descr == NULL) {
		printf("Errore durante pcap_open : %s \n",errbuf);

		return 1;
	}
	else{
		if(argc==4)
			printf("Stream offline aperto correttamente\n");
		else
			printf("Cattura pacchetti in modalità live iniziata\n");
	}
	
	//se non è uno stream wifi non mi interessa
 	if(pcap_datalink(descr)==DLT_IEEE802_11_RADIO)//fastidioso eclipse non è un errore
		{
 		if(!file_exists(LOG_FILE))
 			createLog(LOG_FILE);
 		if( access(LOG_FILE, W_OK ) == -1 ){
 			printf("Errore impossibile scrivere il file log %s controllare i permessi\n",LOG_FILE);
 			return 1;
 		}

		fp = fopen(LOG_FILE, "w");

		printf(MSG_RADIOTAPE);
		send(sd, MSG_RADIOTAPE, strlen(MSG_RADIOTAPE), 0);

		// start packet processing loop, just like live capture
		if (pcap_loop(descr, 0, packetHandler, NULL) < 0) {
			printf("Errore durante pcap_loop() : %s \n", pcap_geterr(descr));

			return 1;
		}
		
		fclose(fp);
		
		//printf("Fine cattura pacchetti\n");
	}
 	else{
		printf(MSG_NO_RADIOTAPE);
		send(sd, MSG_NO_RADIOTAPE, strlen(MSG_NO_RADIOTAPE), 0);
		return 1;
 	}
 
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

void eap_mgmt(const u_char* packet, struct ieee80211_radiotap_header *rh, struct mgmt_header_t *mac_header, int socketDescr){
	//WARNING controllare la lunghezza dei pacchetti prima di fare getcounter e getnonce

	setEap(getNonce(packet), getCounter(packet), mac_header->sa, mac_header->da, socketDescr);
	/*int i;

			for(i=0; i<EAP_NONCE_SIZE;i++)
				printf("%.2x:", chall.snonce[i]);
			printf("\n");

		*/
	}


void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	//ether_type = ntohs(eptr->ether_type);

	printf("."); //stampo un punto per ogni pacchetto che arriva
	fflush(stdout); //flush, altrimenti aspetta un newline...

	struct ieee80211_radiotap_header *rh =(struct ieee80211_radiotap_header *)packet;


	struct mgmt_header_t *mac_header = (struct mgmt_header_t *) (packet+rh->it_len);

	
	fprintf(fp, "PACCHETTO NUMERO : %d, dimensione pacchetto: %d \n", n_pacc, pkthdr->caplen); 
	
	if(pkthdr->caplen < 49) //questo controllo andrebbe fatto prima di prendere i dati dal pacchetto con gli struct
		fprintf(fp, "Pacchetto piccolo\n"); //scarto i pacchetti senza dati
	else if(!u_char_differ(mac_header->da, BROADCAST, MAC_SIZE))
		fprintf(fp, "Pacchetto broadcast\n"); //scarto i pacchetti broadcast
	else if(!u_char_differ((u_char *) (packet +rh->it_len+ sizeof(struct mgmt_header_t)), EAP, EAP_SIZE)){
		//WARNING controllare la lunghezza dei pacchetti prima di fare getcounter e getnonce
		eap_mgmt(packet, rh, mac_header, sd);
		}
	if((mac_header->fc & 0xff) == FC_BEACON){
		//lunghezza dello ssid
		u_int8_t * ssidLength = (u_char *) (packet +rh->it_len+ sizeof(struct mgmt_header_t) + sizeof(u_char)*13);

		//puntatore all'inizio del ssid
		u_char * ssid = (u_char *) (ssidLength + sizeof(u_char));
		
		u_char str_ssid[*ssidLength+1];
		memcpy(str_ssid, ssid, *ssidLength);
		
		str_ssid[*ssidLength]= '\0';
		
		setBeacon(str_ssid, mac_header->sa, sd);

		//printf("ssid %s\n",str_ssid);
		}
	else if((mac_header->fc & 0xff) == FC_DATA){
		setData((struct pcap_pkthdr*)(pkthdr) , (unsigned char *)(packet), sd);
	}


	n_pacc++;

}
