#include <stdio.h>
#include <stdlib.h>

#include "receive.h"

int main(int argc, char ** argv)
{
        if(argc < 2)
        {
                printf("Usage : ./server ip_applicative_server\n");
                return;
        }
	char * ip_server = argv[1];
	receive(ip_server);
	return 0;
}
