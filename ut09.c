/*
  Test exp -> mul 
 */

#include <gmp.h>
#include <paillier.h>


#define NUM_1 -5
#define NUM_2 3

int main(int argc, char *argv[])
{
    // Security parameter (number of bits of the modulus)
    const long n = 256;   
    
    // Generate public and secret keys
    paillier_pubkey_t* pubKey;
    paillier_prvkey_t* secKey;
    paillier_keygen(n, &pubKey, &secKey, paillier_get_rand_devurandom);

    // Plaintexts initialization
    paillier_plaintext_t* m1;
    m1 = paillier_plaintext_from_ui(NUM_1);
    paillier_plaintext_t* m2;
    m2 = paillier_plaintext_from_ui(NUM_2);
    gmp_printf("Plaintexts: \nm1 = %Zx\nm2 = %Zx\n", m1, m2);

    // Encrypt the messages
    paillier_ciphertext_t* ctxt1;
    ctxt1 = paillier_enc(NULL, pubKey, m1, paillier_get_rand_devurandom);
    gmp_printf("Ciphertexts: \nctxt1 = %Zd\n", ctxt1);

    // Initialize the ciphertext with some content 
    paillier_ciphertext_t* encrypted_prod = paillier_create_enc_zero();

    // Multiply the encrypted values by exponentiation
    paillier_exp(pubKey, encrypted_prod, ctxt1, m2);
    gmp_printf("Prod's ciphertext:\n %Zd\n", encrypted_prod);
    
    // Decrypt the ciphertext (sum)
    paillier_plaintext_t* dec;
    dec = paillier_dec(NULL, pubKey, secKey, encrypted_prod);
    gmp_printf("Decrypted: %Zx or (%Zd)\n", dec, dec);

    // Cleaning up
    paillier_freepubkey(pubKey);
    paillier_freeprvkey(secKey);
    paillier_freeplaintext(m1);
    paillier_freeplaintext(m2);    
    paillier_freeplaintext(dec);
    paillier_freeciphertext(ctxt1);
    paillier_freeciphertext(encrypted_prod);
    
    return 0;
}
