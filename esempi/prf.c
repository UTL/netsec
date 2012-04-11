#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>


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
		printf("debug1");
		temp = HMAC(EVP_sha1(), key, key_len, input, total_len, NULL, NULL);
		printf("debug2\n");

		for (k = 0;  k < 20;  k++) printf("%02x ", temp[k]);
			  printf("\n");
		int j;
		for (j=0; j<20;j++){
			printf("%d\n",j);
			output[currentindex+j]=temp[j];

		}
		//hmac_sha1(input, total_len, key, key_len, &output[currentindex]);
		//printf("ciao");
		currentindex += 20;/* next concatenation location */
		input[total_len-1]++; /* increment octet count */
	}
}


void main(){
	printf("debug-1");
	unsigned char * key ="Jefe";
	int key_len = 4; // in byte
	unsigned char * prefix ="prefix";
	int prefix_len= 6; // in byte
	unsigned char * data= "what do ya want for nothing?";
	int data_len = 28;
	unsigned int len = 80; // per gestire l'overflow di sah1
	unsigned char output[len];

	int i =0;
	printf("debug0");

	PRF(key, key_len, prefix, prefix_len, data, data_len,output, len);
	for (i = 0;  i < len;  i++) {
		if((i%16)==0) printf("\n");
		printf("%02x ", output[i]);
	}
	  printf("\n");

}
