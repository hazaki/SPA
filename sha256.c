#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


void print_hash(unsigned char hash[])
{
   int idx;
   for (idx=0; idx < 32; idx++)
      printf("%02x",hash[idx]);
   printf("\n");
}

unsigned char* sha256(unsigned char text[])
{
  unsigned char *hash = malloc(32 * sizeof(unsigned char));
   int idx;
   SHA256_CTX ctx;

   SHA256_Init(&ctx);
   SHA256_Update(&ctx,text,strlen(text));
   SHA256_Final(hash,&ctx);
   
   return hash;
}
/* int main(){ */
/*   unsigned char test[] = {"test"}; */
/*   unsigned char * hash = sha256(test); */
/*   print_hash(hash); */
/*   free(hash); */
/* } */
