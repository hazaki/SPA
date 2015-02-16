#include <sys/unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "encrypt_decrypt.h"
#include "forgery.h"

int LEN_TIME=14;

unsigned char *key = "01234567890123456789012345678901";
unsigned char *iv = "01234567890123456";

int main(int argc, char ** argv)
{
	if(argc < 6)
	{
		printf("Usage : ./client num_port protocol (tcp/udp) time(1-30 sec) interface dest_ip\n");
		return -1;
	}

	char ctime[14];
	time_t now = time( NULL);
	struct tm now_tm = *localtime(&now);

	strftime(ctime, 100, "%Y%m%d%H%M%S", &now_tm);

	unsigned char * num_port = argv[1];

	char sec[2];
	sprintf(sec, "%02d", atoi(argv[3]));

	if(atoi(sec) > 30)
	{
		printf("30 sec maximum\n");
		exit(-1);
	}

	char * protocol = argv[2];

//	if(!check_protocol(protocol))
//		return -1;

	char * interface = argv[4];
	char * dest_ip = argv[5];

	//Recovering SRC IP address

	struct ifaddrs *ifaddr, *ifa;
    	int family, s;
    	char host[NI_MAXHOST];

    	if (getifaddrs(&ifaddr) == -1)
    	{
        	perror("getifaddrs");
        	exit(EXIT_FAILURE);
    	}


    	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    	{
        	if (ifa->ifa_addr == NULL)
            		continue;

        	s=getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

        	if((strcmp(ifa->ifa_name,interface)==0)&&(ifa->ifa_addr->sa_family==AF_INET))
		{
			if (s != 0)
            		{
                		printf("getnameinfo() failed: %s\n", gai_strerror(s));
                		exit(EXIT_FAILURE);
            		}
            		break;
		}
    	}
    	freeifaddrs(ifaddr);

	//Payload Creation
	char data[LEN_TIME + strlen(num_port) + 2 + strlen(host) + strlen(protocol)];
	memcpy(data, host, strlen(host));
	memcpy(data + strlen(host), num_port, strlen(num_port));
	memcpy(data + strlen(host) + strlen(num_port), protocol, strlen(protocol));
	memcpy(data + strlen(host) + strlen(num_port) + strlen(protocol), sec, 2);
	memcpy(data + +strlen(host) + strlen(num_port) + strlen(protocol) + 2, ctime, LEN_TIME);

	data[strlen(host) + LEN_TIME + strlen(num_port) + strlen(protocol) + 2]='\0';
	printf("data : %s\n",data);

	unsigned char cipherpayload[128 + 32];

	int payload_len = get_ciphered_payload(data,key,iv, cipherpayload);

	forge(interface, dest_ip, cipherpayload, payload_len);

	return 0;
}
