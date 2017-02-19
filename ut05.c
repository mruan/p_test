/*
  Test homomorphism

 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmp.h>
#include <paillier.h>

int test_homomorphism(int a,
		      int b,
		      paillier_pubkey_t* pub,
		      paillier_prvkey_t* prv)
{
  printf("a = %d\nb = %d\na+b = %d\n", a, b, a+b);
  printf("a = %u\nb = %u\na+b = %u\n", a, b,  (unsigned int)a+ (unsigned int)b);

  // convert a and b to plaintext
  paillier_plaintext_t* m_a = paillier_plaintext_from_bytes(&a, sizeof(a));
  gmp_printf("m_a -> c_a: %Zd\n", m_a);
  paillier_ciphertext_t* c_a = paillier_enc(NULL, pub, m_a,
					    paillier_get_rand_devurandom);

  paillier_plaintext_t* m_b = paillier_plaintext_from_bytes(&b, sizeof(b));
  gmp_printf("m_b -> c_b: %Zd\n", m_b);
  paillier_ciphertext_t* c_b = paillier_enc(NULL, pub, m_b,
					    paillier_get_rand_devurandom);
  
  // Initialize the ciphertext that will hold the sum with an encryption of zero
  paillier_ciphertext_t* c_sum = paillier_create_enc_zero();
 
  // Sum the encrypted values by multiplying the ciphertexts
  printf("c_a * c_b\n");
  paillier_mul(pub, c_sum, c_a, c_b);

  // decrypt the sum/prod ciphertext
  paillier_plaintext_t* m_sum = NULL;
  m_sum = paillier_dec(NULL, pub, prv, c_sum);

  gmp_printf("c_sum -> m_sum: %Zd\n", m_sum);

  void* bytes = paillier_plaintext_to_bytes(sizeof(int), m_sum);
  int sum = *((int*) bytes);
  free(bytes);

  printf("sum = %d\n", sum);

  paillier_freeplaintext(m_a);
  paillier_freeplaintext(m_b);
  paillier_freeplaintext(m_sum);
  paillier_freeciphertext(c_a);
  paillier_freeciphertext(c_b);
  paillier_freeciphertext(c_sum);
}

int test_homomorphism_u(unsigned int a,
			unsigned int b,
			paillier_pubkey_t* pub,
			paillier_prvkey_t* prv)
{
  //  printf("a = %d\nb = %d\na+b = %d\n", a, b, a+b);
  printf("a = %u\nb = %u\na+b = %u\n", a, b,  a + b);

  // convert a and b to plaintext
  paillier_plaintext_t* m_a = paillier_plaintext_from_bytes(&a, sizeof(a));
  gmp_printf("m_a -> c_a: %Zd\n", m_a);
  paillier_ciphertext_t* c_a = paillier_enc(NULL, pub, m_a,
					    paillier_get_rand_devurandom);

  paillier_plaintext_t* m_b = paillier_plaintext_from_bytes(&b, sizeof(b));
  gmp_printf("m_b -> c_b: %Zd\n", m_b);
  paillier_ciphertext_t* c_b = paillier_enc(NULL, pub, m_b,
					    paillier_get_rand_devurandom);
  
  // Initialize the ciphertext that will hold the sum with an encryption of zero
  paillier_ciphertext_t* c_sum = paillier_create_enc_zero();
 
  // Sum the encrypted values by multiplying the ciphertexts
  printf("c_a * c_b\n");
  paillier_mul(pub, c_sum, c_a, c_b);

  // decrypt the sum/prod ciphertext
  paillier_plaintext_t* m_sum = NULL;
  m_sum = paillier_dec(NULL, pub, prv, c_sum);

  gmp_printf("c_sum -> m_sum: %Zd\n", m_sum);

  void* bytes = paillier_plaintext_to_bytes(sizeof(a), m_sum);
  unsigned int sum = *((unsigned int*) bytes);
  free(bytes);

  printf("sum = %d\n", sum);

  paillier_freeplaintext(m_a);
  paillier_freeplaintext(m_b);
  paillier_freeplaintext(m_sum);
  paillier_freeciphertext(c_a);
  paillier_freeciphertext(c_b);
  paillier_freeciphertext(c_sum);
}

int main()
{
  const int key_len = 64;
  paillier_pubkey_t* pub = NULL;
  paillier_prvkey_t* prv = NULL;

  printf("Create a pair of %d-byte keys\n", key_len);

  paillier_keygen(key_len, &pub, &prv, paillier_get_rand_devurandom);

  char* pub_str = paillier_pubkey_to_hex( pub );
  char* prv_str = paillier_prvkey_to_hex( prv );

  printf("Public key in hex: %s\n", pub_str);
  printf("Private key in hex: %s\n", prv_str);

  //test_homomorphism( 11, 12, pub, prv);
  // test_homomorphism( -11, -22, pub, prv); 
  test_homomorphism_u(4294967285, 4294967274, pub, prv);
  //  test_homomorphism(-1, -2, pub, prv);
  //  test_homomorphism( 2, -1, pub, prv); 
  //  test_homomorphism(12345,  54321, pub, prv);  

  free(pub_str);
  free(prv_str);
  
  paillier_freepubkey(pub);
  paillier_freeprvkey(prv);
  return 0;
}
