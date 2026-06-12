int g_counter;
void driver(void);
void target(long value);

int main(void) {
  g_counter = 1;
  driver();
  return 0;
}

void driver(void) {
  ((void (*)(long))target)(0);
}

void target(long value) {
  (void)value;
}
