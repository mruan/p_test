#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmp.h>
#include <paillier.h>

/*
  Convert a (signed) interger to an unsigned int 
  then create a mesage from it. Finally take it back
  from the message
 */
int test_conversion(long int a)
{
  printf("Conversion test for %ld\n", a);
  unsigned long int b = a;

  paillier_plaintext_t* m_b = paillier_plaintext_from_bytes(&b, sizeof(b));

  void* byte_array = paillier_plaintext_to_bytes(sizeof(unsigned long int), m_b);

  unsigned long int c = *((unsigned long int*) byte_array);
  long int d = (long int) c;

  printf("a=%ld\n", a);
  printf("b=%lu\n", b);
  printf("c=%lu\n", c);
  printf("d=%ld\n", d);

  free(byte_array);
  paillier_freeplaintext(m_b);

  printf("Conversion test for %ld finished.\n", a);
  return 0;
}

int main()
{
  test_conversion(1);
  test_conversion(-1);
  test_conversion(123456);
  test_conversion(-123456);
  return 0;
}
