#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

unsigned char * PTK (unsigned char *key, unsigned char * ANonce, unsigned char * SNonce, unsigned char * AA, unsigned char * SA);

void PRF(unsigned char *key, int key_len,unsigned char *prefix, int prefix_len,unsigned char *data, int data_len,unsigned char *output, unsigned int len);


char * extochar(char * in, int inLen);



int compare_test_vector(unsigned char * test, unsigned char * toTest, int length);

int chartoint(char car);


//da esadecimale a char
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

// traduce da carattere a intero '0' -> 0 'a'->10
int chartoint(char car){
	int intero = 0;
	intero = car - '0';
	if(intero < 10 && intero > -1)
		return intero;
	else
		return car - 'a' + 10; //caratteri mappati diversamente

}

/*	IN: PSK (credo), 2 Nonce, 2 MAC Address
	OUT: PTK
	Descr: restituisce la PTK, invoca PRF per la computazione
	Test-Vector OK
*/
unsigned char * PTK (unsigned char *key, unsigned char * ANonce, unsigned char * SNonce, unsigned char * AA, unsigned char * SA){
	int i,k;
	unsigned char * output=malloc(80);
	unsigned char data[76];
	unsigned char * minA;
	unsigned char * maxA;
	unsigned char * minNonce;
	unsigned char * maxNonce;

	k=0;

	maxA=AA;
	minA=SA;

	if(strcmp(AA,SA)<0){//AS maggiore
		maxA=SA;
		minA=AA;
	}


	for(i=0; i<6; i++){
		data[i]=minA[k];
		k++;
	}
	k=0;
	for(i=6;i<12;i++){
		data[i]=maxA[k];
		k++;
	}

	maxNonce=ANonce;
	minNonce=SNonce;

	if(strcmp(ANonce,SNonce)<0){//SNONCE maggiore
		maxNonce=SNonce;
		minNonce=ANonce;
	}

	k=0;
	for(i=12; i<44; i++){
		data[i]=minNonce[k];
		k++;
	}
	k=0;
	for(i=44;i<76;i++){
		data[i]=maxNonce[k];
		k++;
	}

	//len=80 per gestire overflow di sha 1 in PRF, in realtà output = 64 byte= 512 bit
	PRF(key,32,"Pairwise key expansion",22,data,76,output,80);

	return output;
}

/*
 * computa la PTK
 * Test vector OK
 */
void PRF(
	unsigned char *key, int key_len,
	unsigned char *prefix, int prefix_len,
	unsigned char *data, int data_len,
	unsigned char *output, unsigned int len)
{
	int i;
	unsigned char input[1024]; /* concatenated input */
	int currentindex = 0;
	int total_len;
	memcpy(input, prefix, prefix_len);
	input[prefix_len] = 0; /* single octet 0 */

	memcpy(&input[prefix_len+1], data, data_len);
	total_len = prefix_len + 1 + data_len;

	input[total_len] = 0; /* single octet count, starts at 0 */
	total_len++;
	unsigned char * temp;
	int k;

	for (i = 0; i < (len+19)/20; i++) {
		temp = HMAC(EVP_sha1(), key, key_len, input, total_len, NULL, NULL);

		for (k = 0;  k < 20;  k++) printf("%02x ", temp[k]);
			  printf("\n");
		int j;

		for (j=0; j<20;j++){
			output[currentindex+j]=temp[j];

		}

		currentindex += 20;/* next concatenation location */
		input[total_len-1]++; /* increment octet count */
	}
}

void check_prf(){

	unsigned char * key =extochar("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",40);
	int key_len = 20; // in byte
	unsigned char * prefix ="prefix";
	int prefix_len= 6; // in byte
	unsigned char * data= "Hi There";
	int data_len = 8;
	unsigned int len = 80;
	unsigned char output[len];

	unsigned char * test = extochar("bcd4c650b30b9684951829e0d75f9d54b862175ed9f00606e17d8da35402ffee75df78c3d31e0f889f012120c0862beb67753e7439ae242edb8373698356cf5a",80);
	int k ;


	PRF(key, key_len,prefix, prefix_len,data,  data_len,output, len);

	if(compare_test_vector(test, output, 40)) //40 ne testa solo il primo pezzo, bisognerebbe contare la lunghezza di expected_output
		printf("PRF TEST VECTOR: OK");
	else 
		printf("PRF TEST VECTOR: ERROR");
	}

	int compare_test_vector(unsigned char * test, unsigned char * toTest, int length){
		int i;
		for(i=0; i<length; i++){
			if(test[i] != toTest[i])
				return 0;
		}
		return 1;
	}

void main(){
	check_prf();
/*
	printf("debug-10\n");
	unsigned char * key =extochar("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",40);
	int key_len = 20; // in byte
	unsigned char * prefix ="prefix";
	int prefix_len= 6; // in byte
	unsigned char * data= "Hi There";
	int data_len = 8;
	unsigned int len = 80;
	unsigned char * output; //[len];

	

	unsigned char tk[16];

	//Test vector OK per PTK
	unsigned char * PMK = extochar("0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af", 64);
	unsigned char * AA = extochar("a0a1a1a3a4a5",12);
	unsigned char * SPA = extochar("b0b1b2b3b4b5",12);
	unsigned char * SNONCE = extochar("c0c1c2c3c4c5c6c7c8c9d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5",64);
	unsigned char * ANONCE = extochar("e0e1e2e3e4e5e6e7e8e9f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405",64);

	int i =0;
	printf("debug0\n");

	output = PTK(PMK, ANONCE, SNONCE, AA, SPA);

	for (i = 0;  i < len;  i++) {
		if((i%16)==0) printf("\n");
		printf("%02x ", output[i]);
	}
	printf("\n prova tk \n");
	//TK: sono i bit di PTK da 256 a 383 (PTK 256 128)
	
		

	//memcpy(&tk, &output, 1);
	//tk[10]=0;
	int ix = 0;
	for(ix=0; ix < 16; ix++)
       	 	tk[ix] = output[32+ix];
	tk[16]=0; // non sono sicuro che questo ci vada!

	for (i = 0;  i < 16;  i++) {
		if((i%16)==0) printf("\n");
		printf("%02x ", tk[i]);
	}
	printf("\n prova tk \n");
	
	 // printf("\n");
	 // printf("%d\nUNO\n",(int)'1'-(int)'0');

*/

	/*
	 * da fare:
	 * 1) 	estrarre TK da PTK, vedi http://www.velocityreviews.com/forums/t316034-substring.html, guardare lo standard ed estrarla dal test vector
	 *	fatto, verificare se ci va uno 0 in fondo o meno
	 * espandere la (chiave dell'utente) PSK, con la funzione già esistente (funzione file Frasten)
	 * cercare la funzione CCM in OPENSSL
	 * estrarre a mano i campi dei pacchetti da wireshark
	 * provare la funzione CCM
	 * curiosare nelle librerie pcap
	 * estrarre dati con le pcap
	 *
	 */
}
