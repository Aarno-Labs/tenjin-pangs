// Multi-icall executable fixture for the M1.8 dynamic harness.
//
// Two distinct global function pointers, each stored and then called indirectly at a
// distinct source line. This is the executable counterpart of
// fixtures/synthetic/m1_4b/two_global_fnptrs.pir.json — it exercises the callsite-key
// ordinal path that previously dropped the *second* icall edge from callgraph.jsonl
// (see ju_steens_overmerge_bug.md). `check-traces` must confirm both observed targets are
// in the analysis edge set.
#include <stdio.h>

// Externally visible so the trace runtime's dladdr can resolve the observed target back
// to a symbol name — making check-traces validate the (caller, idx, target) match rather
// than passing permissively on an unresolved `?`.
void alpha(void) { printf("alpha\n"); }
void beta(void) { printf("beta\n"); }

void (*ga)(void);
void (*gb)(void);

int main(void) {
    ga = alpha;
    ga();
    gb = beta;
    gb();
    return 0;
}
