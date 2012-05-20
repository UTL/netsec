#ifndef UTILS_H
#define UTILS_H

#define PWD_SIZE 63
#define TK_SIZE 128
#define NONCE_SIZE 32
#define COUNTER_SIZE 8
#define MAC_SIZE 6

struct mgmt_header_t {
    u_int16_t    fc;          /* 2 bytes */
    u_int16_t    duration;    /* 2 bytes */
    u_int8_t     da[6];       /* 6 bytes */
    u_int8_t     sa[6];       /* 6 bytes */
    u_int8_t     bssid[6];    /* 6 bytes */
    u_int16_t    seq_ctrl;    /* 2 bytes */
} __attribute__ (( packed ));

//struct challenge_data chall;

struct ieee80211_radiotap_header{
    u_int8_t it_version;
    u_int8_t it_pad;
    u_int16_t it_len;
    u_int32_t it_present;
}__attribute__ (( packed ));

char * extochar(char * in);

int chartoint(char car);

int compare_test_vector(unsigned char * test, unsigned char * toTest, int length);

void printhex(unsigned char * toPrint, int length);

int u_char_differ(unsigned char *a, unsigned char *b, int size);

int compare_test_vector(unsigned char * test, unsigned char * toTest, int length);

int isNull(unsigned char * str, int len);

#endif
