#define _BSD_SOURCE 1

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <net/ethernet.h>

#ifdef LINUX
#include <netinet/ether.h>
#endif

#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <fcntl.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>


int main(){
	struct bpf_program filter;     /* The compiled filter       */
	pcap_t *descr;                 /* Session descr             */
	char *dev;                     /* The device to sniff on    */
	char errbuf[PCAP_ERRBUF_SIZE]; /* Error string              */
	struct bpf_program filter;     /* The compiled filter       */
	bpf_u_int32 mask;              /* Our netmask               */
	bpf_u_int32 net;               /* Our IP address            */
	u_char* args = NULL;           /* Retval for pcacp callback */


}
