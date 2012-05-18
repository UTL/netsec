#ifndef UTILS_H
#define UTILS_H

#define PWD_SIZE 63
#define TK_SIZE 128
#define NONCE_SIZE 32
#define COUNTER_SIZE 8
#define MAC_SIZE 6

char * extochar(char * in);

int chartoint(char car);

int compare_test_vector(unsigned char * test, unsigned char * toTest, int length);

void printhex(unsigned char * toPrint, int length);

int u_char_differ(unsigned char *a, unsigned char *b, int size);

int compare_test_vector(unsigned char * test, unsigned char * toTest, int length);

int isNull(unsigned char * str, int len);

#endif
