#include <stdlib.h>
#include "utils.h"

long plaintext_to_long(paillier_plaintext_t* m)
{
  //  paillier_plaintext_t* m = paillier_dec(NULL, pubKey, prvKey, c);

  size_t nBytes = 0;
  unsigned char* bytes = (unsigned char*) mpz_export(0, &nBytes, 1, 1, 0, 0, m->m);

  long int e = 0;
  size_t i = 0;
  //  assert( nBytes > sizeof(a));
  //  for(int i=nBytes-1; i >= nBytes-sizeof(a); --i)
  for(i= nBytes-sizeof(long); i < nBytes; i++)
  {
      e = (e << 8) | bytes[i];
  }

  //  paillier_freeplaintext(m);
  free(bytes);
  return e;
}
