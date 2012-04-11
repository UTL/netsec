#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

//test vector secondo RFC funzionante
/* http://www.faqs.org/rfcs/rfc2202.html
test_case =     2
key =           "Jefe"
key_len =       4
data =          "what do ya want for nothing?"
data_len =      28
digest =        0xeffcdf6ae5eb2fa2d27416d5f184df9c259a7c79

*/

void main(){
	char * key ="Jefe";
	int key_len = 4; // in byte
	unsigned char * d ="what do ya want for nothing?";
	int n= 28; // in byte
	unsigned char * md = "";
	int md_len = 20;

	md = HMAC(EVP_sha1(), key, key_len, d, n, NULL, NULL);

	int i;
	for(i=0; i < md_len; i++){
		printf("%02x", md[i]);
	}
	printf("\n");

}
