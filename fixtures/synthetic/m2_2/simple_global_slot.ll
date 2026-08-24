@Slot = internal global void ()* @cb

define internal void @cb() {
entry:
  ret void
}

define i32 @main() {
entry:
  %fp = load void ()*, void ()** @Slot
  call void %fp()
  ret i32 0
}
