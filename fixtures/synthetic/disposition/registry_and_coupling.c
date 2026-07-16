typedef void (*signal_handler)(int);
typedef int (*spawn_api)(void *, const void *, void *(*)(void *), void *);

struct disposition_sigaction {
  signal_handler handler;
};

extern int pthread_create(void *, const void *, void *(*)(void *), void *);
extern signal_handler signal(int, signal_handler);
extern int sigaction(int, const struct disposition_sigaction *, void *);
extern void register_worker(void *(*)(void *));

int left_state;
int right_state;
int handler_only_state;
int custom_state;
int indirect_worker_state;
int sigaction_handler_state;

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

void *indirect_worker(void *unused) {
  (void)unused;
  indirect_worker_state = 4;
  return 0;
}

void sigaction_handler(int value) { sigaction_handler_state = value; }

void install_callbacks(void) {
  void *(*start)(void *) = worker;
  pthread_create(0, 0, start, 0);
  signal(2, handler);
  register_worker(custom_worker);

  spawn_api launch = pthread_create;
  launch(0, 0, indirect_worker, 0);

  struct disposition_sigaction action;
  action.handler = sigaction_handler;
  sigaction(3, &action, 0);
}
