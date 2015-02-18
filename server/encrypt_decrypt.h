#ifndef ENCRYPT_DECRYPT_H
#define ENCRYPT_DECRYPT_H

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void hmac(char * seed, int cmpt);

int get_unciphered_payload(unsigned char *cipherpayload,  unsigned char *key,
			   unsigned char *iv, unsigned char * plaintext, int cipherpayload_len, unsigned char * hash);
int get_ciphered_payload(unsigned char *plaintext,  unsigned char *key,
			  unsigned char *iv, unsigned char * cipherpayload);
#endif
