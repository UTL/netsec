/*
 * File: client.c
 * Autore: Iezzi Alessandro
 * Client d'esempio
 */
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
 
#define MAX 8192 /* in bytes, 8KB */
 
int main() {
	int sd; /* Il socket descriptor del client */
	struct sockaddr_in server_addr; /* l'indirizzo del server */
	char buff[MAX]; /* dati di invio e ricezione */
 
/* Utilizzando la struttura hostent si definisce l'indirizzo del server */
	struct hostent *hp;
	hp = gethostbyname("127.0.0.1");
 
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(12345);
/* successivamente viene memorizzato nella struttura server_addr */
	server_addr.sin_addr.s_addr = ((struct in_addr*)(hp->h_addr)) -> s_addr;
 
/* Viene creato il socket descriptor */
	if((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		printf("Errore nella creazione della socket\n");
 
/* Viene connesso al server */
	if(connect(sd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
		printf("Errore di connessione al server\n");
 
	printf("sto per inviare i dati\n");
/* Si inviano alcuni dati */
	send(sd, "Dati inviati dal client\n", strlen("Dati inviati dal client\n"), 0);
 	printf("dati inviati\n");
/* Si riceve la risposta */
	send(sd, "Dati inviati dal client2\n", strlen("Dati inviati dal client2\n"), 0);
	send(sd, '\0', 1, 0);
	close(sd);
	return EXIT_SUCCESS;
}
