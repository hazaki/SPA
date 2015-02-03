#include "connected.h"

struct connected * init_connected(int max_connections){
  struct connected * connect = malloc(sizeof(struct connected));
  connect->first = NULL;
  connect->nb_request = 0;
  connect->max_request = max_connections;
  return connect;
}

void close_connections(connected * connect){
  while(connect->first !=NULL)
    del_request(connect);
  free(connect);
}
/*value returned:   meaning:
  1                 valid connection added in the structure
  0                 entry already present in the structure
  -1                invalid time
  -2                full
*/
int add_request(struct connected *connect, unsigned char * hash,char * ip,
		 int port, time_t time_req)
{
  if(connect->nb_request >= connect->max_request)
    return -2;

  if(check_already_present(connect,hash))
    return 0;

  time_t now = time(NULL);
  if((now + 30 <= time_req)||(time_req <=now))
    return -1;

  struct request * new_request = malloc(sizeof(struct request));
  memcpy(new_request->hash,hash,32);
  memcpy(new_request->ip,ip,15);
  new_request->port = port;

  new_request->end_time = time_req;

  if(connect->first ==NULL){
    connect->first = new_request;
    new_request->next = NULL;
  }
  else{
    struct request *current_req = connect->first;

    if(difftime(new_request->end_time, current_req->end_time) <=0)
      {
	connect->first= new_request;
	new_request->next = current_req;
      }
    else{
      struct request * next_req = connect->first->next;
      bool insert = false;
      while(next_req != NULL && !insert)
	{
	  if(difftime(new_request->end_time, next_req->end_time)>0){
	      current_req = next_req;
	      next_req = next_req->next;
	    }
	  else
	    insert = true;

	}
      new_request->next = next_req;
      current_req->next = new_request;
    }
  }
  connect->nb_request++;
  return 1;
}


void del_request(struct connected * connect){
  struct request * req = connect->first;
  printf("first %s\n", req->hash);
  connect->first = connect->first->next;
  req->next = NULL;
  free(req);
  return;
}

bool check_already_present(struct connected * connect, unsigned char *hash){
  struct request * current = connect->first;
  while(current !=NULL){

    if ( strncmp(hash, current->hash,32) ==0){
	//print_hash(hash);
	//print_hash(current->hash);
	//printf("end time : %s\n", asctime(localtime(&current->end_time)));
	return true;
    }
    current = current->next;
  }
  return false;
}

void print_requests(struct connected * connect){
  struct request * current = connect->first;
  while(current !=NULL){
    printf("###################################\n");
    print_hash(current->hash);
    printf("ip : %s\nport : %d\n",current->ip,current->port);
    printf("end time : %s\n", asctime(localtime(&current->end_time)));
    current = current->next;
  }
  return;
}
