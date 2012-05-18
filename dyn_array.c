#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "dyn_array.h"
#include "utils.h"

#define BY_MAC 1
#define BY_COUNTER 2
#define BY_SSID 3

struct challenge_data *the_array = NULL;

int     eap_elements = 0; // Keeps track of the number of elements used
int     eap_allocated = 0; // This is essentially how large the array is

char * ssid;
char * pw;
unsigned char * ap_mac;

void deleteArray(){
	free(the_array);
	}

struct challenge_data * getI(int i){
	if(i<num_elements)
		return (struct challenge_data *)(the_array + i*sizeof(struct challenge_data));
	return NULL;
	}

void setSsid(char * newSsid){
	ssid = (char * )(malloc(sizeof(newSsid)));
	strcpy(ssid,newSsid);
	}

void setApMac(unsigned char * mac){
	if(ap_mac == NULL){
		ap_mac = (unsigned char * )(malloc(sizeof(MAC_SIZE)));
		memcpy(ap_mac, mac, MAC_SIZE);
		}
	}

void setPw(char * newPw){
	pw = malloc(sizeof(newPw));
	strcpy(pw,newPw);
	}

struct challenge_data * getChall(unsigned char * var, int type){
	int i;
	for(i=0; i < num_elements; i++){
		switch(type){
		case BY_MAC:
			if(!u_char_differ(getI(i)->smac, var, MAC_SIZE) || !u_char_differ(getI(i)->dmac, var, MAC_SIZE))
				return getI(i);
		case BY_COUNTER:
			if(!u_char_differ(getI(i)->counter, var, COUNTER_SIZE))
				return getI(i);
		case BY_SSID:
			if(!u_char_differ(var, ssid, strlen(ssid)))
				return getI(i);
		}
	}
	return NULL;
	}

struct challenge_data * getByMac(unsigned char * s){
	return getChall(s, BY_MAC);
	}

	struct challenge_data * getByCounter(unsigned char * c){
		return getChall(c, BY_COUNTER);
	}
	
struct challenge_data *getBySsid(char * c){
	return getChall(c, BY_COUNTER);
	}



void setEap(unsigned char * nonce, unsigned char * count){
	if()
	}

int pushTo(struct challenge_data item)
{
        if(num_elements == num_allocated) // Are more refs required?
        {
                // Feel free to change the initial number of refs
                // and the rate at which refs are allocated.
                if (num_allocated == 0)
                        num_allocated = 3; // Start off with 3 refs
                else
                        num_allocated *= 2; // Double the number
                                                    // of refs allocated

                // Make the reallocation transactional
                // by using a temporary variable first
                void *_tmp = realloc(the_array, (num_allocated * sizeof(struct challenge_data)));

                // If the reallocation didn't go so well,
                // inform the user and bail out
                if (!_tmp)
                {
                        fprintf(stderr, "ERROR: Couldn't realloc memory!\n");
                        return(-1);
                }

                // Things are looking good so far
                the_array = (struct challenge_data*)_tmp;
        }

        the_array[num_elements] = item;
        num_elements++;

        return num_elements;
}
