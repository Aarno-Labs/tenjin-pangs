#include <stdarg.h>

const char *first_pointer(int tag, ...) {
  va_list ap;
  va_start(ap, tag);
  const char *value = va_arg(ap, const char *);
  va_end(ap);
  return value;
}

const char *pointer_tail(int tag, ...) {
  va_list ap;
  const char *value;
  va_start(ap, tag);
  do {
    value = va_arg(ap, const char *);
  } while (value != 0);
  va_end(ap);
  return value;
}

const char *copied_list(int tag, ...) {
  va_list ap;
  va_list copy;
  va_start(ap, tag);
  va_copy(copy, ap);
  const char *value = va_arg(copy, const char *);
  va_end(copy);
  va_end(ap);
  return value;
}
