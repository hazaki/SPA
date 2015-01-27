#include <stdio.h>
#include <stdlib.h>

#include "encrypt_decrypt.h"
#include "forgery.h"

unsigned char *key = "01234567890123456789012345678901";
unsigned char *iv = "01234567890123456";

int main(int argc, char ** argv)
{
	if(argc < 4)
	{
		printf("Usage : ./client num_port interface dest_ip\n");
		return -1;
	}

	char * num_port = argv[1];
	char * interface = argv[2];
	char * dest_ip = argv[3];
	char cyphertext[128];

	encrypt(num_port, strlen(num_port), key, iv, cyphertext);
	forge(interface, dest_ip, cyphertext);

	return 0;
}
