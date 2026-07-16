int phase_value;

int main(int argc, char **argv) {
  (void)argv;
  phase_value = 0;
  if (argc > 1) {
    phase_value = 1;
  } else {
    phase_value = 2;
  }
  while (argc-- > 2) {
    phase_value += argc;
  }
  phase_value = 3; phase_value = 4;
  return phase_value;
}
