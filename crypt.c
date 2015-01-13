//gcc -lssl -lcrypto crypt.c -o crypt
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

unsigned char key[] = {
        0x01, 0x22, 0x04, 0x0e, 0x01, 0x22, 0x04, 0x0e,
        0x01, 0x22, 0x04, 0x0e, 0x01, 0x22, 0x04, 0x0e,
        0x01, 0x22, 0x04, 0x0e, 0x01, 0x22, 0x04, 0x0e,
        0x01, 0x22, 0x04, 0x0e, 0x01, 0x22, 0x04, 0x0e,
        };

unsigned char iv_enc[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
        };

unsigned char iv_dec[AES_BLOCK_SIZE];

int main()
{
        unsigned char in[256] = "123456789abcdefghijklmnopqrstuvwxyz";
        unsigned char crypt[256];
        unsigned char out[256];
        int len = strlen(in);

        //padding
        while (len % 16 != 0)
        {
                in[len]=0;
                len++;
        }

        memcpy(iv_dec, iv_enc, AES_BLOCK_SIZE);

        AES_KEY aes_key, aes_key2;

        AES_set_encrypt_key(key, 256, &aes_key);
        AES_cbc_encrypt(in, crypt, len, &aes_key, iv_enc, AES_ENCRYPT);
        //AES_encrypt(premier, deuxieme, &aes_key);

        printf("encrypte : %s\n", crypt);
        len = ((len + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	
	    AES_set_decrypt_key(key, 256, &aes_key2);
	    AES_cbc_encrypt(crypt, out, len, &aes_key2, iv_dec, AES_DECRYPT);
	    //AES_decrypt(deuxieme, troisieme, &aes_key2);
	
	    printf("décrypte : %s\n", out);
	
	return 0;
}
