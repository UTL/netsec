#ifndef PRF_PTK_H_   /* Include guard */
#define PRF_PTK_H_

unsigned char * calc_tk(unsigned char * human_readable_pw, unsigned char * ssid, unsigned char* sa, unsigned char* da, unsigned char* snonce, unsigned char * anonce);

#endif

