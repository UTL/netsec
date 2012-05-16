#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include "utils.h"

#define KEK_KEY_LEN 32
#define ITERATION 4096
#define TK_LEN 16

unsigned char * PTK (unsigned char *key, unsigned char * ANonce, unsigned char * SNonce, unsigned char * AA, unsigned char * SA);

void PRF(unsigned char *key, int key_len,unsigned char *prefix, int prefix_len,unsigned char *data, int data_len,unsigned char *output, unsigned int len);

void check_prf();

void print_check(char * tipo_test, int testOk);


void print_check(char * tipo_test, int testOk){
	printf("TEST VECTOR %s:",tipo_test);
	if(testOk)
		printf(" OK\n");
	else
		printf(" FALLITO\n");
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

		//for (k = 0;  k < 20;  k++) printf("%02x ", temp[k]);
		//	  printf("\n");
		int j;

		for (j=0; j<20;j++){
			output[currentindex+j]=temp[j];

		}

		currentindex += 20;/* next concatenation location */
		input[total_len-1]++; /* increment octet count */
	}
}

//funzione per testare la prf
void check_prf(){
	//Test 1
	unsigned char * key =extochar("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
	int key_len = 20; // in byte
	unsigned char * prefix ="prefix";
	int prefix_len= 6; // in byte
	unsigned char * data= "Hi There";
	int data_len = 8;
	unsigned int len = 80;
	unsigned char output[len];

	unsigned char * test = extochar("bcd4c650b30b9684951829e0d75f9d54b862175ed9f00606e17d8da35402ffee75df78c3d31e0f889f012120c0862beb67753e7439ae242edb8373698356cf5a");

	//Test 2
	unsigned char * key2 =extochar("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
	int key_len2 = 20; // in byte
	unsigned char * prefix2 ="prefix";
	int prefix_len2= 6; // in byte
	unsigned char * data2= extochar("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
	int data_len2 = 50;
	unsigned int len2 = 80;
	unsigned char output2[len2];
	
	unsigned char * test2=extochar("e1ac546ec4cb636f9976487be5c86be17a0252ca5d8d8df12cfb0473525249ce9dd8d177ead710bc9b590547239107aef7b4abd43d87f0a68f1cbd9e2b6f7607");
	
	//Test 3
	unsigned char * key3 = "Jefe";
	int key_len3 = 4; // in byte
	unsigned char * prefix3 ="prefix";
	int prefix_len3= 6; // in byte
	unsigned char * data3 = "what do ya want for nothing?";
	int data_len3 = 28;
	unsigned int len3 = 80;
	unsigned char output3[len3];
	
	unsigned char * test3= extochar("51f4de5b33f249adf81aeb713a3c20f4fe631446fabdfa58244759ae58ef9009a99abf4eac2ca5fa87e692c440eb40023e7babb206d61de7b92f41529092b8fc");
	
	unsigned char * key4 = extochar("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
	int key_len4 = 20; // in byte
	unsigned char * prefix4 ="prefix-4";
	int prefix_len4= 8; // in byte
	unsigned char * data4 = "Hi There Again";
	int data_len4 = 14;
	unsigned int len4 = 80;
	unsigned char output4[len4];
	
	unsigned char * test4= extochar("248cfbc532ab38ffa483c8a2e40bf170eb542a2e0916d7bf6d97da2c4c5ca877736c53a65b03fa4b3745ce7613f6ad68e0e4a798b7cf691c96176fd634a59a49");


	PRF(key, key_len,prefix, prefix_len,data,  data_len,output, len);
	print_check("PRF 1", compare_test_vector(test, output, 40));

		
	PRF(key2, key_len2,prefix2, prefix_len2,data2,  data_len2, output2, len2);
	print_check("PRF 2", compare_test_vector(test2, output2, 40));
	
	
	PRF(key3, key_len3,prefix3, prefix_len3,data3,  data_len3,output3, len3);
	print_check("PRF 3", compare_test_vector(test3, output3, 40));
	
	PRF(key4, key_len4,prefix4, prefix_len4,data4,  data_len4,output4, len4);
	print_check("PRF 4", compare_test_vector(test4, output4, 40));
	}



//input ptk pieno, output unsigned char tk
unsigned char * tk_extract(unsigned char *ptk){
	unsigned char *tk = (unsigned char*)malloc(sizeof(unsigned char)*16);
	
	//TK: sono i bit di PTK da 256 a 383 (PTK 256 128)
	//memcpy(&tk, &output, 1);
	int k;
	for (k = 32;  k < 48;  k++) 
		tk[k-32] = ptk[k];
	return tk;
	}
		//wrapper da testare
void pbkdf2(char *pass, unsigned char *salt,unsigned char *out){
		PKCS5_PBKDF2_HMAC_SHA1(pass, strlen(pass), salt, strlen(salt), ITERATION, KEK_KEY_LEN, out);
	}

void check_ptk(){
	//Test vector OK per PTK
	unsigned char * PMK = extochar("0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af");
	unsigned char * AA = extochar("a0a1a1a3a4a5");
	unsigned char * SPA = extochar("b0b1b2b3b4b5");
	unsigned char * SNONCE = extochar("c0c1c2c3c4c5c6c7c8c9d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5");
	unsigned char * ANONCE = extochar("e0e1e2e3e4e5e6e7e8e9f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405");
	unsigned char * tk;
	unsigned char * ptk;
	unsigned char * test = extochar("b2360c79e9710fdd58bea93deaf06599");
	
	ptk = PTK(PMK, ANONCE, SNONCE, AA, SPA);
	tk = tk_extract(ptk);
	
	print_check("TK 1", compare_test_vector(test, tk, 16));
	
	}
	
check_pbkdf2(){
	int KEK_KEY = 20; //32
	int ITERA = 1; //4096
	
	size_t i;
	unsigned char *out;
	const char pwd[] = "password";
	unsigned char salt_value[] = "salt";

	out = (unsigned char *) malloc(sizeof(unsigned char) * KEK_KEY);
	
	//NB non usare il wrapper con valori diversi non funziona!
	PKCS5_PBKDF2_HMAC_SHA1(pwd, strlen(pwd), salt_value, strlen(salt_value), ITERA, KEK_KEY, out);
	
	unsigned char * test = extochar("0c60c80f961f0e71f3a9b524af6012062fe037a6");
	
	print_check("PKCS5 1", compare_test_vector(test, out, KEK_KEY));
	
	unsigned char *out2;
	KEK_KEY = 32; //32
	ITERA = 4096;
	out2 = (unsigned char *) malloc(sizeof(unsigned char) * KEK_KEY);
	char pwd2[] = "angelatramontano";
	unsigned char salt_value2[] = "Sitecom";
	out = (unsigned char *) malloc(sizeof(unsigned char) * KEK_KEY);
	pbkdf2(pwd2, salt_value2, out2);
	unsigned char * test2= extochar("00d13bfb75506b72134478095b567600f5f3e68f62ec842878f0ce5e1d360bb9");
	
	print_check("PKCS5 PICCI", compare_test_vector(test2, out2, KEK_KEY));
	//printhex(out2, KEK_KEY_LEN);
	}
	

unsigned char * calc_tk(unsigned char * human_readable_pw, unsigned char * ssid, unsigned char* sa, unsigned char* da, unsigned char* snonce, unsigned char * anonce){
	
	unsigned char *pmk = (unsigned char *) malloc(sizeof(unsigned char) * KEK_KEY_LEN);
	
	pbkdf2(human_readable_pw, ssid, pmk);
	
	unsigned char *bigK = PTK(pmk, anonce, snonce, sa, da);
	
	return tk_extract(bigK);
	}

	
	//testa tutto fino alla tk
void check_picci_stream(){
	
	unsigned char *pmk;
	const char pwd[] = "angelatramontano";
	unsigned char ssid[] = {'S','i','t','e','c','o','m'};
	
	pmk = (unsigned char *) malloc(sizeof(unsigned char) * KEK_KEY_LEN);
	
	PKCS5_PBKDF2_HMAC_SHA1(pwd, strlen(pwd), ssid, sizeof(ssid), ITERATION, KEK_KEY_LEN, pmk);
	
	unsigned char * AP= extochar("000cf635dfab");
	unsigned char * STA = extochar("74f06d40a6a3");
	unsigned char * Anonce = extochar("d5c0958cc32b7b3ae762c43b41436059e54cb48f224d35718613838d9640644d");
	unsigned char * Snonce = extochar( "fbf9fbe50feae721f3e9991b810bab7e601e53de7455dc6ca29802f0ea34cb24");
	
	unsigned char *bigK = PTK(pmk, Anonce, Snonce, AP, STA);
	
	unsigned char * tk = tk_extract(bigK);
	
	//printhex(tk, TK_LEN);
	
	unsigned char * test_tk = extochar("c7134fd10709f028d63c2e05cbb4c16c");
	
	print_check("PICCI STREAM", compare_test_vector(test_tk, tk, TK_LEN));
	
	char pwd2[] = "angelatramontano";
	tk = calc_tk(pwd2, ssid, AP, STA, Anonce,Snonce);
	
	print_check("PICCI STREAM 2", compare_test_vector(test_tk, tk, TK_LEN));
	
	
	} 

void main(){
	check_pbkdf2();
	check_prf();
	check_ptk();

	//testa tutto fino alla tk
	check_picci_stream();

	/*
	 * da fare:
	 * cercare la funzione CCM in OPENSSL
	 * provare la funzione CCM
	 */
}
