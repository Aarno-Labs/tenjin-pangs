#include <stdarg.h>

int sum_first(int n, ...) {
  va_list ap;
  va_start(ap, n);
  int value = va_arg(ap, int);
  va_end(ap);
  return value + n;
}
