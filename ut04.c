/*
  Test if I need to store the sign bit to do the multiplication

  => at least for the example given below I don't have to
 */

#include <stdio.h>
#include <stdlib.h>

int test_mul(long int a, long int b)
{
  printf("int a = %ld\nint b = %ld\n", a, b);
  /*
    case 1: both positive
    case 2: both negative
    case 3: different sign
    case 4: is zero?
   */

  //  bool sign_a = !(a < 0); // a >= 0
  //  bool sign_b = !(b < 0); // b >= 0

  unsigned long int ua = (unsigned long int) a;
  unsigned long int ub = (unsigned long int) b;

  unsigned long int uab = ua * ub;
  long int p_uab = (long int) uab;
  
  long int p_sab = a * b;

  printf("ua*ub = %lu\n", uab);
  printf("p_uab = %ld\n", p_uab);
  printf("p_sab = %ld\n\n", p_sab);
}

int main()
{
  test_mul(12345, 54321);
  test_mul(-12345, 54321);
  test_mul(12345, -54321);
  test_mul(-12345, -54321);

  return 0;
}
