declare i32 @vararg_target(i8*, ...)
declare x86_fp80 @x87_id(x86_fp80)
declare void @accept_short_cb(void (i8*)*)

define void @short_cb(i8* %p) {
entry:
  ret void
}

define void @driver(i8* %p, i64 %bits, x86_fp80 %xf) {
entry:
  call i32 (i8*, ...) @vararg_target(i8* %p, i64 %bits, i8* %p)
  call x86_fp80 @x87_id(x86_fp80 %xf)
  call void @accept_short_cb(void (i8*)* @short_cb)
  ret void
}
