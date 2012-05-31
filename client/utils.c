#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "utils.h"

void printhex(unsigned char * toPrint, int length){
	int k;
	for (k = 0;  k < length;  k++) 
		printf("%02x ", toPrint[k]);
	
	printf("\n");
	}

unsigned char * u_char_increase(unsigned char * in, int size){
	unsigned char overflow = 1;
	unsigned char * t = (unsigned char *)(malloc(size*sizeof(unsigned char)));
	unsigned char * out = t;
	
	memcpy(t,in, size);
	t = t + (size-1)*sizeof(unsigned char);
	
	while(size-- && overflow){
		if(overflow)
			(*t)++;
		overflow = !(*t);
		t--;
		}

	return out;// - (size-1);
	}

char * extochar(char* string)
{
    unsigned char * out = malloc(sizeof(unsigned char)*strlen(string)/2);
    int i;
    for (i = 0; i < strlen(string)/2; i++)
    {
        sscanf(&string[2*i], "%02x", (unsigned int *)(&out[i]));
    }
    return out;
}

int u_char_differ(unsigned char *a, unsigned char *b, int size) {
	while(size -- > 0) {
		if ( *a != *b ) 
			return 1;
		a++; b++;
	}
	return 0;
}


int compare_test_vector(unsigned char * test, unsigned char * toTest, int length){
		return !u_char_differ(test, toTest, length);
	}
	
	
int isNull(u_char * str, int len){
	while(len -- > 0) {
		if ( *str != '\0' ) 
			return 0;
		str++;
	}
	return 1;
	}
	

