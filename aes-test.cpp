/* 
 * aes-test.c
 * by John Heidemann
 *
 * inspired by code by Ben Miller
 * (Small sample for how to use Blowfish from OpenSSL
 *  http://www.eecis.udel.edu/~bmiller/cis364/2012s/hw/hw3/code/blowfish-test.c)
 *
 * Sadly, as of 2012-10-01 and openssl-1.0.0j
 * there are no manual pages for AES in openssl's libcrypto.
 * However, the header file /usr/include/openssl/aes.h
 * and the manual pages for blowfish(3) are a reasonable starting point.
 *
 * Compile in Linux (tested with Fedora-17) with:
 *	gcc -o $@ -g aes-test.c -lcrypto
 *
 */

/* uncomment next line to build a library by removing main(). */
#define IS_LIBRARY 
#include "aes-test.h"

void class_AES_set_encrypt_key(unsigned char *key_text, AES_KEY *enc_key)
{
	AES_set_encrypt_key(key_text, AES_KEY_LENGTH_IN_BITS, enc_key);
}

void class_AES_set_decrypt_key(unsigned char *key_text, AES_KEY *dec_key)
{
	AES_set_decrypt_key(key_text, AES_KEY_LENGTH_IN_BITS, dec_key);
}

void class_AES_encrypt(unsigned char *in, unsigned char *out, int len, AES_KEY *enc_key)
{
	unsigned char ivec[AES_KEY_LENGTH_IN_BITS/8];
	/*
	 * Don't use a 0 IV in the real world,
	 * see http://en.wikipedia.org/wiki/Initialization_vector for why. 
	 * Fortunately class projects are not the real world.
	 */
	memset(ivec, 0, sizeof(ivec)); 
	AES_cbc_encrypt(in, out, len, enc_key, ivec, AES_ENCRYPT);
}

void class_AES_decrypt(unsigned char *in, unsigned char *out, int len, AES_KEY *dec_key)
{
	unsigned char ivec[AES_KEY_LENGTH_IN_BITS/8];
	/*
	 * Don't use a 0 IV in the real world,
	 * see http://en.wikipedia.org/wiki/Initialization_vector for why. 
	 * Fortunately class projects are not the real world.
	 */
	memset(ivec, 0, sizeof(ivec)); 
	AES_cbc_encrypt(in, out, len, dec_key, ivec, AES_DECRYPT);
}

void class_AES_encrypt_with_padding(unsigned char *in, int len, unsigned char **out, int *out_len, AES_KEY *enc_key)
{
	/*
	 * Don't use a 0 IV in the real world,
	 * see http://en.wikipedia.org/wiki/Initialization_vector for why. 
	 * Fortunately class projects are not the real world.
	 */
	unsigned char ivec[AES_KEY_LENGTH_IN_BITS/8];
	memset(ivec, 0, sizeof(ivec)); 
	/*
	 * AES requires iput to be an exact multiple of block size
	 * (or it doesn't work).
	 * Here we implement standard pading as defined in PKCS#5
	 * and as described in 
	 * <http://marc.info/?l=openssl-users&m=122919878204439>
	 * by Dave Stoddard.
	 */
	int padding_required = AES_KEY_LENGTH_IN_CHARS - len % AES_KEY_LENGTH_IN_CHARS;
	if (padding_required == 0) /* always must pad */
		padding_required += AES_KEY_LENGTH_IN_CHARS;
	assert(padding_required > 0 && padding_required <= AES_KEY_LENGTH_IN_CHARS);
	int padded_len = len + padding_required;

	unsigned char *padded_in = new unsigned char [padded_len] ;//() malloc(padded_len);
	assert(padded_in != NULL);
	memcpy(padded_in, in, len);
	memset(padded_in + len, 0, padded_len - len);
	padded_in[padded_len-1] = padding_required;

	*out = new unsigned char [padded_len];//malloc(padded_len);
	assert(*out);  
	*out_len = padded_len;

	/* finally do it */
	AES_cbc_encrypt(padded_in, *out, padded_len, enc_key, ivec, AES_ENCRYPT);
}

/*
 * class_AES_decrypt:
 * decrypt IN of LEN bytes
 * into a newly malloc'ed buffer
 * that is returned in OUT of OUT_LEN bytes long
 * using DEC_KEY.
 *
 * It is the *caller*'s job to free(out).
 * In and out lengths will always be different because of manditory padding.
 */
void class_AES_decrypt_with_padding(unsigned char *in, int len, unsigned char **out, int *out_len, AES_KEY *dec_key)
{
	unsigned char ivec[AES_KEY_LENGTH_IN_BITS/8];
	/*
	 * Don't use a 0 IV in the real world,
	 * see http://en.wikipedia.org/wiki/Initialization_vector for why. 
	 * Fortunately class projects are not the real world.
	 */
	memset(ivec, 0, sizeof(ivec));
	*out = new unsigned char[len]; //malloc(len);
	assert(*out);

	AES_cbc_encrypt(in, *out, len, dec_key, ivec, AES_DECRYPT);

	/*
	 * Now undo padding.
	*/
	int padding_used = (int)(*out)[len-1];
	//unsigned char *p = *out + (len-1);
	//int padding_used = (int)*p;
	assert(padding_used > 0 && padding_used <= AES_KEY_LENGTH_IN_CHARS); 

	*out_len = len - padding_used;
	
	//print_packet_hex((char*)*out, len);
	/*
	 * We actually return a malloc'ed buffer that is longer
	 * then out_len, but the memory system takes care of that for us. 
	 */

}


#ifndef IS_LIBRARY
int main()
{
	unsigned char *key_text = "password1234568";  /* NOT a good password :-) */
	unsigned char key_data[AES_KEY_LENGTH_IN_CHARS];
	unsigned char *clear_text = "Four score and seven years ago our fathers brought forth on this continent a new nation, conceived in liberty, and dedicated to the proposition that all men are created equal.";
	int buflen = strlen(clear_text) + 1; /* add one for null termination */

	unsigned char *crypt_text = malloc(buflen);
	unsigned char *clear_crypt_text = malloc(buflen);

	AES_KEY enc_key;
	AES_KEY dec_key;

	/*
	 * Fill in the 128-bit binary key with some text
	 * better would be to compute the sha1 has of the text,
	 * but this is OK for a class project.
	 */
	memset(key_data, 0, sizeof(key_text));
	strncpy(key_data, key_text, MIN(strlen(key_text), sizeof(key_data)));

	if (crypt_text == NULL || clear_crypt_text == NULL) {
		printf("malloc failed\n");
		exit(1);
	};

	/* test out encryption */
	class_AES_set_encrypt_key(key_text, &enc_key);
	class_AES_encrypt(clear_text, crypt_text, buflen, &enc_key);
	printf("%s\n", crypt_text);

	class_AES_set_decrypt_key(key_text, &enc_key);
	class_AES_decrypt(crypt_text, clear_crypt_text, buflen, &enc_key);
	printf("%s\n", clear_crypt_text);

	exit(0);
}
#endif
