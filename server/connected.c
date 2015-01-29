#include "connected.h"

struct connected * init_connected(){
  struct connected * connect = malloc(sizeof(struct connected));
  connect->first = NULL;
  connect->nb_request = 0;
  return connect;
}

void add_request(struct connected *connect, unsigned char * hash,char * ip,
		 int port, time_t time)
{
  struct request * new_request = malloc(sizeof(struct request));
  new_request->hash = hash;
  new_request->ip = ip;
  new_request->port = port;
  /* new_request->end_time = *((time_t*) malloc(sizeof(time_t))) */;
				 
  new_request->end_time = time;			 
  
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
  return;
}


void del_request(struct connected * connect){
  struct request * req = connect->first;
  printf("first %s\n", req->hash);
  connect->first = connect->first->next;
  req->next = NULL;
  /* free(&req->end_time) */;
  free(req);
  return;
}

bool check_already_present(struct connected * connect, unsigned char *hash){
  struct request * current = connect->first;
  while(current !=NULL){
    printf("cmp :%s , %s\n", current->hash, hash);
    if ( strcmp(hash, current->hash) ==0){
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
    printf("hash : %s\n",current->hash);
    /* print_hash(current->hash) */;
    printf("ip : %s\nport : %d\n",current->ip,current->port);
    printf("end time : %s", asctime(localtime(&current->end_time)));
    current = current->next;
      
  }
  return;
}

int main(){
  struct connected * connect = init_connected();
  time_t now =time(NULL);
  unsigned char * add1 = "firstadd";
  add_request(connect,add1, "",12, now);
  print_requests(connect);
  printf("####################################\n\n\n");
  unsigned char * add2 = "secondtadd";
  add_request(connect,add2, "",13, now -1);
  print_requests(connect);
  printf("####################################\n\n\n");
  unsigned char * add3 = "thirdtadd";
  add_request(connect,add3, "",14, now -2); 
  print_requests(connect);
  printf("####################################\n\n\n");

  /* del_request(connect); */
  printf("strcmp : %d\n", strcmp(add1, connect->first->next->next->hash));
  printf("%d %s\n",check_already_present(connect,"yfuvgyi"),"yfuvgyi");

  print_requests(connect);
  printf("####################################\n\n\n");

  printf("delete\n");
  del_request(connect);

  
  print_requests(connect);
  printf("####################################\n\n\n");
  del_request(connect);
  del_request(connect);
  free(connect);
  return 0;
}
