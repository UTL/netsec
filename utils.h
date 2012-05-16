#ifndef UTILS_H
#define UTILS_H

char * extochar(char * in);

int chartoint(char car);

int compare_test_vector(unsigned char * test, unsigned char * toTest, int length);

void printhex(unsigned char * toPrint, int length);

int u_char_differ(unsigned char *a, unsigned char *b, int size);

int compare_test_vector(unsigned char * test, unsigned char * toTest, int length);

int isNull(u_char * str, int len);

#endif
