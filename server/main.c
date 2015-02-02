#include <stdio.h>
#include <stdlib.h>

#include "connected.h"
#include "receive.h"

int MAX_REQUEST = 1024;

int main(int argc, char ** argv)
{
	struct connected * connection = init_connected(MAX_REQUEST);
	receive(connection);
	return 0;
}
