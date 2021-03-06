#include "encrypt_decrypt.h"

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

/********************************/
/****Cryp/Uncrypt whit AES*******/
/********************************/


int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}

/********************************/
/*********HASH WITH SHA256*******/
/********************************/

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

/********************************/
/**************HMAC**************/
/********************************/

void hmac(char * seed, int cmpt, int len, char * password)
{
    unsigned char* digest;
    unsigned char counter[20];
    sprintf(counter, "%d", cmpt);
    digest = HMAC(EVP_sha1(), seed, len, counter, strlen(counter), NULL, NULL);

    // Be careful of the length of string with the choosen hash engine. SHA1 produces a 20-byte hash value which rendered as 40 characters.
    // Change the length accordingly with your choosen hash engine
    for(int i = 0; i < 20; i++)
         sprintf(&password[i*2], "%02x", (unsigned int)digest[i]);

    printf("HMAC digest: %s\n", password);
}

/********************************/
/******Create correct payload****/
/********************************/

int get_ciphered_payload(unsigned char *plaintext,  unsigned char *key,
				    unsigned char *iv, unsigned char * cipherpayload)
{
  unsigned char ciphertext[128];

  int plaintext_len = strlen(plaintext);
  int cipher_len = encrypt(plaintext,plaintext_len, key,iv,ciphertext);
  ciphertext[cipher_len]='\0';

  unsigned char * cipherhash = sha256(ciphertext);

  memcpy(cipherpayload, ciphertext, cipher_len);
  memcpy(cipherpayload + cipher_len, cipherhash, 32);
  memcpy(cipherpayload + cipher_len + 32, iv, 16);

  return cipher_len + 32 + 16;

}
int check_hash(unsigned char *ciphertext, unsigned char *hash){
  unsigned char * ciphertext_hash = sha256(ciphertext);
  if(strncmp(hash,ciphertext_hash,32)==0)
    return 1;
  return 0;

}
int get_unciphered_payload(unsigned char *cipherpayload,  unsigned char *key,
			    unsigned char * plaintext, int cipherpayload_len, unsigned char * hash)
{
  unsigned char iv[16];
  int ciphertext_len = cipherpayload_len - 32 - 16;
  unsigned char ciphertext[ciphertext_len];
  memcpy(ciphertext, cipherpayload, ciphertext_len);
  memcpy(hash, cipherpayload + ciphertext_len, 32);
  memcpy(iv, cipherpayload + ciphertext_len + 32, 16);

  ciphertext[ciphertext_len]='\0';

  if (!check_hash(ciphertext, hash)){
    fprintf(stderr, "Invalid authentication");
    exit(-1);
  }

  int plaintext_len = decrypt(ciphertext,ciphertext_len, key,iv,plaintext);

  return plaintext_len;
}
