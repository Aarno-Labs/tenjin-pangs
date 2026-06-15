#include <stdio.h>

void target(void) { printf("target\n"); }

typedef void (*fn)(void);

fn g;

int main(void) {
    g = target;
    g();              /* indirect call resolved to `target` */
    return 0;
}
