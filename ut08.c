/*
  Test homomorphism

 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmp.h>
#include <paillier.h>

int test_arithmetic(unsigned long int a,
		    unsigned long int b,
		    unsigned long int c,
		    paillier_pubkey_t* pub,
		    paillier_prvkey_t* prv)
{
  printf("a = %ld\nb = %ld\n", a, b);
  printf("c = %ld\nc(a+b) = %ld\n", c, c*(a+b));

  // convert a and b to plaintext
  paillier_plaintext_t* m_a = paillier_plaintext_from_ui(a);
   paillier_ciphertext_t* c_a = paillier_enc(NULL, pub, m_a,
					    paillier_get_rand_devurandom);
   gmp_printf("m_a: %Zd\nc_a: %Zd\n", m_a, c_a);
 

  paillier_plaintext_t* m_b = paillier_plaintext_from_ui(b);
  paillier_ciphertext_t* c_b = paillier_enc(NULL, pub, m_b,
					    paillier_get_rand_devurandom);
  gmp_printf("m_b: %Zd\nc_b: %Zd\n", m_b, c_b);
  
// Initialize the ciphertext that will hold the sum with an encryption of zero
  paillier_ciphertext_t* c_sum = paillier_create_enc_zero();
 
  // Sum the encrypted values by multiplying the ciphertexts
  printf("c_a * c_b\n");
  paillier_mul(pub, c_sum, c_a, c_b);

  paillier_plaintext_t* m_c = paillier_plaintext_from_ui(c);
  paillier_ciphertext_t* c_res = paillier_create_enc_zero();
  paillier_exp(pub, c_res, c_sum, m_c); 

  // decrypt the sum/prod ciphertext
  paillier_plaintext_t* m_res = NULL;
  m_res = paillier_dec(NULL, pub, prv, c_res);

  gmp_printf("c_res -> m_res: %Zd\n", m_res);

  /*
  void* bytes = paillier_plaintext_to_bytes(sizeof(int), m_res);
  int res = *((int*) bytes);
  free(bytes);
  */
  char temp_str[128];
  gmp_sprintf(temp_str, "%Zd", m_res);
  long int res = atoi(temp_str);
  printf("res = %ld\n", res);

  paillier_freeplaintext(m_a);
  paillier_freeplaintext(m_b);
  //  paillier_freeplaintext(m_sum);
  paillier_freeplaintext(m_c);
  paillier_freeciphertext(c_a);
  paillier_freeciphertext(c_b);
  paillier_freeciphertext(c_sum);
  paillier_freeciphertext(c_res);
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
 
  test_arithmetic(12345, 54321, 2,  pub, prv);  

  free(pub_str);
  free(prv_str);
  
  paillier_freepubkey(pub);
  paillier_freeprvkey(prv);
  return 0;
}
