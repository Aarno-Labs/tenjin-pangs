struct Big {
  void *a;
  void *b;
  void *c;
};

extern void sink(struct Big);

struct Big ret_big(void *p, void *q, void *r) {
  struct Big x = {p, q, r};
  sink(x);
  return x;
}
