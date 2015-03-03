#ifndef RECEIVE_H
#define RECEIVE_H

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <signal.h>

#include "encrypt_decrypt.h"
#include "connected.h"
#include "handle_XML_connection_file.h"

void receive(char * ip);

#endif
