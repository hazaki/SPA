#include <stdio.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <string.h>

#include "encrypt_decrypt.h"
#include "forgery.h"
#include "handle_XML_connection_file.h"

int LEN_TIME=14;

#define HMAC_LEN 40

unsigned char *key = "01234567890123456789012345678901";
unsigned char *iv = "0123456789012345";

int main(int argc, char ** argv)
{
	if(argc < 6)
	{
		printf("Usage : ./client num_port protocol (tcp/udp) time(1-30 sec) interface dest_ip\n");
		return -1;
	}

	//Argument Recovering
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
	printf("interface : %s\n",interface);
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

	//Payload Parsing

	char data[LEN_TIME + strlen(num_port) + 2 + strlen(host) + strlen(protocol)];
	memcpy(data, host, strlen(host));
	memcpy(data + strlen(host), num_port, strlen(num_port));
	memcpy(data + strlen(host) + strlen(num_port), protocol, strlen(protocol));
	memcpy(data + strlen(host) + strlen(num_port) + strlen(protocol), sec, 2);
	memcpy(data + +strlen(host) + strlen(num_port) + strlen(protocol) + 2, ctime, LEN_TIME);

	data[strlen(host) + LEN_TIME + strlen(num_port) + strlen(protocol) + 2]='\0';
	printf("data : %s\n",data);

	unsigned char cipherpayload[128 + 32];

	//OTP

	xmlDocPtr doc;
	doc = xmlParseFile("connections.xml");
	if (doc == NULL) {
    		fprintf(stderr, "Invalid XML file\n");
    		return EXIT_FAILURE;
  	}

	//recover counter
	int counter;
       	counter = atoi(getCount(doc,host));

       	//recover seed
	char * seed;
	char password[HMAC_LEN];
	seed = getSeed(doc,host);

       	hmac(seed,counter,HMAC_LEN,password);

	int payload_len = get_ciphered_payload(data, password, iv, cipherpayload);

	forge(interface, dest_ip, cipherpayload, payload_len);

	counter++;

	char ccounter[20];
	sprintf(ccounter, "%d", counter);
	printf("counter %s\n",ccounter);

	setCountValue(doc, host, ccounter);

	//writting in XML file
  	FILE* file = NULL;
  	file = fopen("connections.xml", "w");
  	if(file== NULL){
     		fprintf(stderr, "Error while opening file\n");
  	}
  	xmlDocDump(file, doc);

  	fclose(file);

  	// free memory
  	xmlFreeDoc(doc);

	return 0;
}
