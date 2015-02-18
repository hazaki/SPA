#ifndef CONNECTED_H
#define CONNECTED_H

#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "encrypt_decrypt.h"

typedef struct request request;
typedef struct connected connected;

struct request{
  struct request *next;
  unsigned char hash[32];
  char ip[15];
  int port;
  char protocol[3];
  time_t end_time;
};

struct connected{
  struct request * first;
  int nb_request;
  int max_request;
};

int add_request(struct connected *connect, unsigned char * hash,char * ip,
		 int port, char * protocol, time_t time);

struct connected * init_connected(int max_request);

void del_request(struct connected * connect);

bool check_already_present(struct connected * connect, unsigned char *hash);

void close_connections(struct connected * connect);

void print_request(struct connected * connect);

#endif
