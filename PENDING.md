# Pending Ideas/Tasks

### Localization of address-taken compound literal initialized globals

For example, 

```c
static Scope *scope = &(Scope){};
```

in `chibicc/parse.c`.

A closure-aware localization proof should be able to say:

  - put the scope pointer in the context;
  - put an initially zeroed Scope backing object in the same context;
  - initialize the pointer to that context-owned backing object;
  - rewrite all uses of scope through the context.

