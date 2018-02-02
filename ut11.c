/*
  Test c*a
  where c is negative
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#include <gmp.h>
//#include <paillier.h>

#include "utils.h" // for plaintext_to_long()

int test_prod(unsigned long int a,
		unsigned long int c,
		paillier_pubkey_t* pub,
		paillier_prvkey_t* prv)
{
  printf("a = %ld(%lu)\n", a, a);
  printf("c = %ld(%lu)\n", c, c);
  printf("ca = %ld(%lu)\n",c*a,c*a);

  paillier_plaintext_t* m_a = paillier_plaintext_from_ui(a);
 paillier_ciphertext_t* c_a = paillier_enc(NULL, pub, m_a,
					  paillier_get_rand_devurandom);
  gmp_printf("m_a: %Zd\nc_a: %Zd\n", m_a, c_a);
 
  paillier_plaintext_t* m_c = paillier_plaintext_from_ui(c);
  paillier_ciphertext_t* c_res = paillier_create_enc_zero();
  paillier_exp(pub, c_res, c_a, m_c); 

  // decrypt the sum/prod ciphertext
  paillier_plaintext_t* m_res = NULL;
  m_res = paillier_dec(NULL, pub, prv, c_res);
  gmp_printf("c_res -> m_res: %Zd\n", m_res);

  // char temp_str[128];
  //  gmp_sprintf(temp_str, "%Zd", m_res);
  //  printf("str: %s\n", temp_str);
  //  long int res = atoi(temp_str);
  long int res = plaintext_to_long(m_res);
  printf("res = %ld(%lx)\n", res, res);

  paillier_freeplaintext(m_a);
   //  paillier_freeplaintext(m_sum);
  paillier_freeplaintext(m_c);
  paillier_freeciphertext(c_a);
  paillier_freeciphertext(c_res);
}


int main()
{
  // Security parameter (number of bits of the modulus)
  const long n = 256;   
    
  // Generate public and secret keys
  paillier_pubkey_t* pubKey;
  paillier_prvkey_t* secKey;
  paillier_keygen(n, &pubKey, &secKey, paillier_get_rand_devurandom);

// (a, c, pubkey, seckey)
  test_prod(5, 23, pubKey, secKey);
  test_prod(-5, 23, pubKey, secKey);
    
  paillier_freepubkey(pubKey);
  paillier_freeprvkey(secKey);
}
