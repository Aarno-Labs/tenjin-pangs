static int configured;

static void initialize(void) { configured = 7; }

static void publication_boundary(void) {}

int main(void) {
  initialize();
  publication_boundary();
  return configured;
}
