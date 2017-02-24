/*
  Test c*(a + (-b))
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmp.h>
#include <paillier.h>

int test_comp(long int a,
	      long int b,
	      long int c,
	      paillier_pubkey_t* pub,
	      paillier_prvkey_t* prv)
{
  printf("a = %ld\nb = %ld\nc = %ld\n", a, b, c);
  // Plaintexts initialization
  paillier_plaintext_t* m_a = paillier_plaintext_from_ui(a);
  paillier_plaintext_t* m_b = paillier_plaintext_from_ui(b);
  paillier_plaintext_t* m_c = paillier_plaintext_from_ui(c);
  gmp_printf("Plaintexts: \nm_a = %Zx\nm_b = %Zx\n", m_a, m_b);
  gmp_printf("m_c = %Zx\n", m_c);

  // Encrypt messages
  paillier_ciphertext_t* c_a = NULL;
  c_a = paillier_enc(NULL, pub, m_a, paillier_get_rand_devurandom);
  paillier_ciphertext_t* c_b = NULL;
  c_b = paillier_enc(NULL, pub, m_b, paillier_get_rand_devurandom);
  gmp_printf("Ciphertexts: \nc_a = %Zd\nc_b = %Zd\n", c_a, c_b);

  // Initialize the ciphertext to zero
  paillier_ciphertext_t* c_d1 = paillier_create_enc_zero();
  paillier_ciphertext_t* c_d2 = paillier_create_enc_zero();

  // Sum the encrypted values by multiplying the ciphertexts
  paillier_mul(pub, c_d1, c_a, c_b);
  gmp_printf("Sum's ciphertext: %Zd\n", c_d1);

  // Decrypt the ciphertext (sum)
  paillier_plaintext_t* m_d1 = paillier_dec(NULL, pub, prv, c_d1);
  gmp_printf("Decrypted d1: %Zx\n", m_d1);

  // Multiply the difference
  paillier_exp(pub, c_d2, c_d1, m_c);
  gmp_printf("Prod's ciphertext: %Zd\n", c_d2);

  // Decrypt the ciphertext (sum)
  paillier_plaintext_t* m_d2 = paillier_dec(NULL, pub, prv, c_d2);
  gmp_printf("Decrypted d2: %Zx\n", m_d2);

  paillier_freeplaintext(m_a);
  paillier_freeplaintext(m_b); 
  paillier_freeplaintext(m_c); 
  paillier_freeplaintext(m_d1);
  paillier_freeplaintext(m_d2);
  paillier_freeciphertext(c_d1);
  paillier_freeciphertext(c_d2);
  paillier_freeciphertext(c_a);
  paillier_freeciphertext(c_b);

  return 0;
}

int main()
{
  // Security parameter (number of bits of the modulus)
  const long n = 256;   
    
  // Generate public and secret keys
  paillier_pubkey_t* pubKey;
  paillier_prvkey_t* secKey;
  paillier_keygen(n, &pubKey, &secKey, paillier_get_rand_devurandom);

  test_comp(15, -5, 23, pubKey, secKey);
  
  paillier_freepubkey(pubKey);
  paillier_freeprvkey(secKey);
}
