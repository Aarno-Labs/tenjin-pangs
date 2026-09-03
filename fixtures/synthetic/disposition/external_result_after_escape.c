static int g;

extern int *external_exchange(int *);

int main(void) {
  (void)external_exchange(&g);
  int *p = external_exchange(0);
  *p = 1;
  return 0;
}
