#ifndef ARRAY_H
#define ARRAY_H

#define PWD_SIZE 63
#define TK_SIZE 128
#define NONCE_SIZE 32
#define COUNTER_SIZE 8
#define MAC_SIZE 6

struct challenge_data{
	unsigned char		anonce[NONCE_SIZE];
	unsigned char		snonce[NONCE_SIZE];
	unsigned char		dmac[MAC_SIZE];
	unsigned char		smac[MAC_SIZE];
	char				ssid[PWD_SIZE+1];
	char				pwd[PWD_SIZE+1];
	unsigned char		tk[TK_SIZE];
	unsigned char		counter[COUNTER_SIZE];
	};
	
struct eapData{
	unsigned char		anonce[NONCE_SIZE];
	unsigned char		snonce[NONCE_SIZE];
	unsigned char		smac[MAC_SIZE];
	unsigned char		counter[COUNTER_SIZE];
	int					status;//stato dell'handshake, cresce coi pacchetti 1 2 3 4, quando arriva a 4 abbiamo finito
	};
	
struct auth{
	unsigned char		staMac[MAC_SIZE];
	unsigned char		tk[TK_SIZE];
	};

int getArraySize();

void deleteArray();

int pushTo(struct challenge_data item);

#endif
