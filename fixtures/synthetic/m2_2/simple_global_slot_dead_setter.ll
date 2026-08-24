@Slot = global void ()* @cb

define internal void @cb() {
entry:
  ret void
}

define void @dead_setter(void ()* %replacement) {
entry:
  store void ()* %replacement, void ()** @Slot
  ret void
}

define i32 @main() {
entry:
  %fp = load void ()*, void ()** @Slot
  call void %fp()
  ret i32 0
}
