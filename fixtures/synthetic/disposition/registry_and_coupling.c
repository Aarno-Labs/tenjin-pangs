typedef void (*signal_handler)(int);

extern int pthread_create(void *, const void *, void *(*)(void *), void *);
extern signal_handler signal(int, signal_handler);
extern void register_worker(void *(*)(void *));

int left_state;
int right_state;
int handler_only_state;
int custom_state;

void *worker(void *unused) {
  (void)unused;
  left_state = 1;
  right_state = 2;
  return 0;
}

void handler(int value) {
  right_state = value;
  handler_only_state = value;
}

void *custom_worker(void *unused) {
  (void)unused;
  custom_state = 3;
  return 0;
}

void install_callbacks(void) {
  void *(*start)(void *) = worker;
  pthread_create(0, 0, start, 0);
  signal(2, handler);
  register_worker(custom_worker);
}
