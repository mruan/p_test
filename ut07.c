/*
  Test encrypting and decrypting messages
  1. 1 -> small in plain text domain
  2. -1-> big in plain text domain
  3. 12345 -> 
  4. -12345 ->
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmp.h>
#include <paillier.h>

int test_exp(unsigned long int a,
	     unsigned long int c,
	     paillier_pubkey_t* pub,
	     paillier_prvkey_t* prv)
{
  printf("a = %lu\nc = %lu\nc*a = %lu\n", a, c, c*a);

  // Convert int to plaintext
  paillier_plaintext_t* m_a = paillier_plaintext_from_ui(a);
  gmp_printf("m_a: %Zd\n", m_a);
  
  // Encrypt plaintext
  paillier_ciphertext_t* c_a = paillier_enc(NULL, pub, m_a,
					    paillier_get_rand_devurandom);

  paillier_ciphertext_t* c_exp = paillier_create_enc_zero();

  paillier_plaintext_t* m_c = paillier_plaintext_from_ui(c);
  gmp_printf("m_c: %Zd\n", m_c);	

  paillier_exp(pub, c_exp, c_a, m_c);

  // Decrypt ciphertext
  paillier_plaintext_t* m_exp = paillier_dec(NULL, pub, prv, c_exp);

  char temp_str[128];
  gmp_printf("m_exp: %Zd\n", m_exp);
  gmp_sprintf(temp_str, "%Zd", m_exp);

  /*
  void* bytes2 = paillier_plaintext_to_bytes(sizeof(unsigned long int), m_exp);
  unsigned long int res = *((unsigned long int*) bytes2);
  free(bytes2);
  */
  long int res = atoi(temp_str);
  printf("res = %ld\n", res);

  paillier_freeplaintext(m_a);
  paillier_freeplaintext(m_c);
  paillier_freeplaintext(m_exp);
  paillier_freeciphertext(c_a);
  paillier_freeciphertext(c_exp);
}
		  
int main()
{
  const int key_len = 128;
  paillier_pubkey_t* pub = NULL;
  paillier_prvkey_t* prv = NULL;

  printf("Create a pair of %d-byte keys\n", key_len);

  paillier_keygen(key_len, &pub, &prv, paillier_get_rand_devurandom);

  char* pub_str = paillier_pubkey_to_hex( pub );
  char* prv_str = paillier_prvkey_to_hex( prv );

  printf("Public key in hex: %s\n", pub_str);
  printf("Private key in hex: %s\n", prv_str);

  test_exp(12345, 12, pub, prv);

  free(pub_str);
  free(prv_str);
  
  paillier_freepubkey(pub);
  paillier_freeprvkey(prv);
  return 0;
}
