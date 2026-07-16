static int left;
static int right;

static void init_left(void) { left = 1; }
static void init_right(void) { right = 2; }

static void initialize(void) {
  init_left();
  init_right();
}

static void publication_boundary(void) {}

int main(void) {
  initialize();
  publication_boundary();
  return left + right;
}
