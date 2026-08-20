@bits = global i64 0
@transfersl = global i64 0

define void @bounded_asm() {
entry:
  call void asm sideeffect "movq $$0, ($0)", "r,~{memory}"(i64* @bits)
  ret void
}

define void @symbol_asm() {
entry:
  call void asm sideeffect "movq bits, %rax", ""()
  ret void
}
