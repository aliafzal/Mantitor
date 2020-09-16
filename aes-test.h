#include "types.h"
#include <openssl/aes.h>
#include <assert.h>

#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))
const int AES_KEY_LENGTH_IN_BITS = 128;
const int AES_KEY_LENGTH_IN_CHARS = 128/8;

void class_AES_set_encrypt_key(unsigned char *key_text, AES_KEY *enc_key);

void class_AES_set_decrypt_key(unsigned char *key_text, AES_KEY *dec_key);

void class_AES_encrypt(unsigned char *in, unsigned char *out, int len, AES_KEY *enc_key);

void class_AES_decrypt(unsigned char *in, unsigned char *out, int len, AES_KEY *dec_key);

void class_AES_encrypt_with_padding(unsigned char *in, int len, unsigned char **out, int *out_len, AES_KEY *enc_key);

void class_AES_decrypt_with_padding(unsigned char *in, int len, unsigned char **out, int *out_len, AES_KEY *dec_key);


