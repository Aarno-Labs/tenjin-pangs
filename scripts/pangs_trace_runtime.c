/* M1.8 dynamic icall trace runtime.
 *
 * Linked into instrumented synthetic fixtures. The instrumentation (pangs-pir) inserts a
 * call to __pangs_trace_icall before every indirect call; this hook resolves the target
 * function pointer to a symbol name via dladdr and appends "<caller>\t<idx>\t<name>" to
 * the file named by $PANGS_TRACE. `pangs check-traces` then asserts every observed
 * (caller, idx, target) pair is in the analysis's indirect-call edge set.
 *
 * Build target functions with external linkage (non-static) so dladdr can name them; link
 * the executable with -rdynamic -ldl.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

void __pangs_trace_icall(const char *caller, int idx, void *target) {
    const char *path = getenv("PANGS_TRACE");
    if (!path) {
        return;
    }
    FILE *f = fopen(path, "a");
    if (!f) {
        return;
    }
    Dl_info info;
    const char *name = "?";
    if (dladdr(target, &info) && info.dli_sname) {
        name = info.dli_sname;
    }
    fprintf(f, "%s\t%d\t%s\n", caller ? caller : "?", idx, name);
    fclose(f);
}
