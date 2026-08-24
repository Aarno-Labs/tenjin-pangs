@Slot = internal global void ()* @cb
@Other = internal constant [4 x i8] c"abc\00"

define internal void @cb() {
entry:
  ret void
}

define i32 @main() {
entry:
  %other = getelementptr [4 x i8], [4 x i8]* @Other, i64 0, i64 0
  %fp = load void ()*, void ()** @Slot
  call void %fp()
  ret i32 0
}
