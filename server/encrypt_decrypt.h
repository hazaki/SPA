#ifndef ENCRYPT_DECRYPT_H
#define ENCRYPT_DECRYPT_H

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


int get_unciphered_payload(unsigned char *cipherpayload,  unsigned char *key,
			   unsigned char *iv, unsigned char * plaintext, int cipherpayload_len, unsigned char hash[]);
int get_ciphered_payload(unsigned char *plaintext,  unsigned char *key,
			  unsigned char *iv, unsigned char * cipherpayload);
void print_hash(unsigned char hash[]);


#endif
