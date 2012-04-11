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
#include <openssl/bn.h>

void spc_incremental_hmac(unsigned char *key, size_t keylen) {
  int           i;
  HMAC_CTX      ctx;
  unsigned int  len;
  unsigned char out[20];

  HMAC_Init(&ctx, key, keylen, EVP_sha1());
  HMAC_Update(&ctx, "fred", 4);
  HMAC_Final(&ctx, out, &len);
  for (i = 0;  i < len;  i++) printf("%02x", out[i]);
  printf("\n");

  HMAC_Init(&ctx, 0, 0, 0);
  HMAC_Update(&ctx, "fred", 4);
  HMAC_Final(&ctx, out, &len);
  for (i = 0;  i < len;  i++) printf("%02x", out[i]);
  printf("\n");
  HMAC_cleanup(&ctx); /* Remove key from memory */
}

void PRF(unsigned char *key, int key_len,unsigned char *prefix, int prefix_len,	unsigned char *data, int data_len,	unsigned char *output, unsigned int len){
		int i,j;
		// concateno come prefix|0|data
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

//confronta e concatena, poi invoca PRF
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

	if(strcmp(AA,SA)<0){//se AS maggiore li inverto
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

	if(strcmp(ANonce,SNonce)<0){//se SNONCE maggiore li inverto
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

void main() {
  spc_incremental_hmac("ciao", 5);
	BIGNUM static_bn, *dynamic_bn;
	BN_init(&static_bn);
	dynamic_bn = BN_new();
	BN_free(dynamic_bn);
	BN_free(&static_bn);
	printf("myfunction\n");
}

