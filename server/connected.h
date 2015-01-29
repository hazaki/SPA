#ifndef CONNECTED_H
#define CONNECTED_H

#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
/* #include "encrypt_decrypt.h" */

typedef struct request request;
typedef struct connected connected;

struct request{
  struct request *next;
  unsigned char * hash;
  char * ip;
  int port;
  time_t end_time;
};

struct connected{
  struct request * first;
  int nb_request;
};

void add_request(struct connected *connect, unsigned char * hash,char * ip,
		 int port, time_t time);

struct connected * init_connected();

void del_request(struct connected * connect);

bool check_already_present(struct connected * connect, unsigned char *hash);
  
#endif
