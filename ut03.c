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

int test_recovery(int a,
		  paillier_pubkey_t* pub,
		  paillier_prvkey_t* prv)
{
  printf("a = %d\n", a);

  // Convert int to plaintext
  paillier_plaintext_t* m_a1 = paillier_plaintext_from_bytes(&a, sizeof(a));

  void* bytes1 = paillier_plaintext_to_bytes(sizeof(int), m_a1);
  int b1 = *((int*) bytes1);
  free(bytes1);
  printf("b1= %d\n", b1);
  
  // Encrypt plaintext
  paillier_ciphertext_t* c_a1 = paillier_enc(NULL, pub, m_a1,
					    paillier_get_rand_devrandom);

  /* // This chunk of code cause core dump
  void* bytesC = paillier_ciphertext_to_bytes(sizeof(int), c_a1);
  int c = *((int*) bytesC);
  free(bytesC);
  printf("c = %d\n", c);
  */
  
  // Decrypt ciphertext
  paillier_plaintext_t* m_a2 = paillier_dec(NULL, pub, prv, c_a1);
  
  void* bytes2 = paillier_plaintext_to_bytes(sizeof(int), m_a2);
  int b2 = *((int*) bytes2);
  free(bytes2);
  printf("b2= %d\n\n", b2);

  paillier_freeplaintext(m_a1);
  paillier_freeciphertext(c_a1);
  paillier_freeplaintext(m_a2);
 
}
		  
int main()
{
  const int key_len = 64;
  paillier_pubkey_t* pub = NULL;
  paillier_prvkey_t* prv = NULL;

  printf("Create a pair of %d-byte keys\n", key_len);

  paillier_keygen(key_len, &pub, &prv, paillier_get_rand_devrandom);

  char* pub_str = paillier_pubkey_to_hex( pub );
  char* prv_str = paillier_prvkey_to_hex( prv );

  printf("Public key in hex: %s\n", pub_str);
  printf("Private key in hex: %s\n", prv_str);

  test_recovery(1, pub, prv);
  test_recovery(-1, pub, prv);
  test_recovery(12345, pub, prv);
  test_recovery(-12345, pub, prv);
  
  free(pub_str);
  free(prv_str);
  
  paillier_freepubkey(pub);
  paillier_freeprvkey(prv);
  return 0;
}
