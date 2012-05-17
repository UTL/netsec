#include <stdlib.h>
#include <stdio.h> 
#include "dyn_array.h"
#include "utils.h"

struct challenge_data *the_array = NULL;

int     num_elements = 0; // Keeps track of the number of elements used
int     num_allocated = 0; // This is essentially how large the array is

int getArraySize(){
	return num_elements;
	}

void deleteArray(){
	free(the_array);
	}

struct challenge_data * getI(int i){
	if(i<num_elements)
		return (struct challenge_data *)(the_array + i*sizeof(struct challenge_data));
	return NULL;
	}

struct challenge_data * getByMac(unsigned char * mac){
	if(num_elements <1)
		return NULL;
	else {
		int i;
		for(i=0; i < num_elements; i++){
			if(!u_char_differ(getI(i)->smac, mac, MAC_SIZE) || !u_char_differ(getI(i)->dmac, mac, MAC_SIZE))
				return getI(i);
			}
		}
	return NULL;
	}
	
	struct challenge_data * getByCounter(unsigned char * counter){
	if(num_elements <1)
		return NULL;
	else {
		int i;
		for(i=0; i < num_elements; i++){
			if(!u_char_differ(getI(i)->counter, counter, COUNTER_SIZE))
				return getI(i);
			}
		}
	return NULL;
	}
	
struct challenge_data *getBySsid(char * ssid){
	if(num_elements <1)
		return NULL;
	else{
		int i;
		 for(i=0; i < num_elements; i++){
			if(!strcmp(ssid, ssid))
				return getI(i);
			}
		}
	return NULL;
	}

int AddToArray (struct challenge_data item)
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
