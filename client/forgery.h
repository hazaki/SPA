#ifndef FORGE_H
#define FORGE_H

#include <stdio.h>
#include <libnet.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>

void forge(char * interface, char * dest_ip, char * text, int payload_len);

#endif
