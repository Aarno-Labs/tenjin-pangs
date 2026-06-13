define void @asm_call() {
entry:
  call void asm sideeffect "", ""()
  ret void
}
