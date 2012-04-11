#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#define A_SHA_DIGEST_LEN 128


void hmac_sha1(unsigned char *key, size_t keylen) {
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

void F(
	char *password,
	unsigned char *ssid,
	int ssidlength,
	int iterations,
	int count,
	unsigned char *output)
	{
		unsigned char digest[36], digest1[A_SHA_DIGEST_LEN];
		int i, j;
		for (i = 0; i < strlen(password); i++) {
			assert((password[i] >= 32) && (password[i] <= 126));
		}

		/* U1 = PRF(P, S || int(i)) */
		memcpy(digest, ssid, ssidlength);
		digest[ssidlength] = (unsigned char)((count>>24) & 0xff);
		digest[ssidlength+1] = (unsigned char)((count>>16) & 0xff);
		digest[ssidlength+2] = (unsigned char)((count>>8) & 0xff);
		digest[ssidlength+3] = (unsigned char)(count & 0xff);
		hmac_sha1(digest, ssidlength+4, (unsigned char*) password, (int) strlen(password), digest, digest1);
		/* output = U1 */
		memcpy(output, digest1, A_SHA_DIGEST_LEN);
		for (i = 1; i < iterations; i++) {
			/* Un = PRF(P, Un-1) */
			hmac_sha1(digest1, A_SHA_DIGEST_LEN, (unsigned char*) password, (int) strlen(password), digest);
			memcpy(digest1, digest, A_SHA_DIGEST_LEN);
			/* output = output xor Un */
			for (j = 0; j < A_SHA_DIGEST_LEN; j++) {
				output[j] ^= digest[j];
			}
		}
	}

	/*
	* password - ascii string up to 63 characters in length
	* ssid - octet string up to 32 octets
	* ssidlength - length of ssid in octets
	* output must be 40 octets in length and outputs 256 bits of key
	*/
int PasswordHash (
	char *password,
	unsigned char *ssid,
	int ssidlength,
	unsigned char *output
)
{
	if ((strlen(password) > 63) || (ssidlength > 32))
		return 0;
	F(password, ssid, ssidlength, 4096, 1, output);
	F(password, ssid, ssidlength, 4096, 2, &output[A_SHA_DIGEST_LEN]);
	return 1;
}



void main(){
	int outlen = 64;
	unsigned char out[64];
	char* password = "password";
	printf("pw: %s\n",password);

	int ssidlength;
	ssidlength = 4;
	unsigned char ssid[] = {'I','E','E','E'};

	int i=0;
	for (i = 0;  i < ssidlength;  i++)
		printf("%02x", ssid[i]);
	printf("\n");

	PasswordHash(password, ssid, ssidlength, out);
	for (i = 0;  i < outlen;  i++)
		printf("%02x", out[i]);
	printf("\n");
}

