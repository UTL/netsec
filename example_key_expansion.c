/*
 * prova_hmac.c
 *
 *  Created on: 14/dic/2010
 *      Author: enrico
 */

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

char * extochar(char * in, int inLen);
int chartoint(char c);
void PRF(unsigned char *key, int key_len,unsigned char *prefix, int prefix_len,	unsigned char *data, int data_len,	unsigned char *output, unsigned int len);

unsigned char * PTK (unsigned char *key, unsigned char * ANonce, unsigned char * SNonce, unsigned char * AA, unsigned char * SA);


int main()
{
//
//NOTA CHE 1 CHAR = 1 BYTE
	int k;


	char * key=extochar("0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af", 64);
	unsigned char * AA=extochar("a0a1a1a3a4a5",12);
	unsigned char * SA=extochar("b0b1b2b3b4b5",12);
	unsigned char * ANonce=extochar("c0c1c2c3c4c5c6c7c8c9d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5",64);
	unsigned char * SNonce=extochar("e0e1e2e3e4e5e6e7e8e9f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405",64);
	//int key_len=32; //in byte
	//unsigned char * data=extochar("a0a1a1a3a4a5 b0b1b2b3b4b5 c0c1c2c3c4c5c6c7c8c9d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5 e0e1e2e3e4e5e6e7e8e9f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405",152);
	//int data_len=76;//in byte
	//unsigned char * prefix ="Pairwise key expansion";
	//int prefix_len=22;
	//unsigned int len=80;//per gestire overflow di sha 1 in PRF, in realtà output = 64 byte= 512 bit



	unsigned char* output;

	output= PTK(key,ANonce,SNonce,AA,SA);




	int i;
	printf("\n\n");
	for (i = 0; i < 64; i++) {
		if((i%16)==0)
			printf("\n");
		printf("%02x ", output[i]);

    }

}


	void PRF(unsigned char *key, int key_len,unsigned char *prefix, int prefix_len,	unsigned char *data, int data_len,	unsigned char *output, unsigned int len){
		int i,j;
		unsigned char input[1024]; /* concatenated input */
		int currentindex = 0;
		int total_len;
		memcpy(input, prefix, prefix_len);
		input[prefix_len] = 0; /* single octet 0 */
		memcpy(&input[prefix_len+1], data, data_len);
		total_len = prefix_len + 1 + data_len;
		input[total_len] = 0; /* single octet count, starts at 0 */
		total_len++;



		unsigned char  * temp;

		for (i = 0; i < (len+19)/20; i++) {

			temp=HMAC(EVP_sha1(),key,key_len,input,total_len,NULL,NULL);

			//20 = numero dei caratteri di output di hmac
			for(j=0; j<20; j++){
				output[currentindex+j]=temp[j];

			}

			currentindex += 20;/* next concatenation location */
			input[total_len-1]++; /* increment octet count */
		}
	}

/*input in formato numero macchina, no caratteri*/
unsigned char * PTK (unsigned char *key, unsigned char * ANonce, unsigned char * SNonce, unsigned char * AA, unsigned char * SA){
	int i,k;
	unsigned char * output=malloc(80);
	unsigned char data[76];
	unsigned char * minA;
	unsigned char * maxA;
	unsigned char * minNonce;
	unsigned char * maxNonce;

	k=0;
	if(strcmp(AA,SA)<0){//AS maggiore
		maxA=SA;
		minA=AA;
	}
	else{
		maxA=AA;
		minA=SA;
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

	if(strcmp(ANonce,SNonce)<0){//SNONCE maggiore
		maxNonce=SNonce;
		minNonce=ANonce;
	}
	else{
		maxNonce=ANonce;
		minNonce=SNonce;
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

int chartoint(char c){
	switch(c){
	case '0':
		return 0;
	case '1':
		return 1;
	case '2':
		return 2;
	case '3':
		return 3;
	case '4':
		return 4;
	case '5':
		return 5;
	case '6':
		return 6;
	case '7':
		return 7;
	case '8':
		return 8;
	case '9':
		return 9;
	case 'a':
		return 10;
	case 'b':
		return 11;
	case 'c':
		return 12;
	case 'd':
		return 13;
	case 'e':
		return 14;
	case 'f':
		return 15;
	}
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
