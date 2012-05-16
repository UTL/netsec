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


//da esadecimale a char
char * extochar(char * in){
	int inLen = strlen(in);
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
	

