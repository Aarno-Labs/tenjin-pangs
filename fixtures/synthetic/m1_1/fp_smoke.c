int g_counter;
void target(long value);
void (*fp)(long) = target;

void target(long value) {
  g_counter = (int)value;
}

void driver(void) {
  fp(7);
}
