#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "encrypt_decrypt.h"
#include "forgery.h"

int LEN_TIME=14;

unsigned char *key = "01234567890123456789012345678901";
unsigned char *iv = "01234567890123456";

int main(int argc, char ** argv)
{
	if(argc < 5)
	{
		printf("Usage : ./client num_port temps(1-30 sec) interface dest_ip\n");
		return -1;
	}

	char ctime[14];
	time_t now = time( NULL);
	struct tm now_tm = *localtime(&now);

	strftime(ctime, 100, "%Y%m%d%H%M%S", &now_tm);

	unsigned char * num_port = argv[1];

	char * sec;
	sprintf(sec, "%02d", atoi(argv[2]));

	if(atoi(sec) > 30)
	{
		printf("30 sec maximum\n");
		exit(-1);
	}

	char * interface = argv[3];
	char * dest_ip = argv[4];

	char data[LEN_TIME + strlen(num_port) + 2];
	memcpy(data, num_port, strlen(num_port));
	memcpy(data + strlen(num_port), sec, 2);
	memcpy(data + strlen(num_port) + 2, ctime, LEN_TIME);

	data[LEN_TIME + strlen(num_port) + 2]='\0';
	printf("data : %s\n",data);

	unsigned char cipherpayload[128 + 32];

	int payload_len = get_ciphered_payload(data,key,iv, cipherpayload);

	forge(interface, dest_ip, cipherpayload, payload_len);

	return 0;
}
