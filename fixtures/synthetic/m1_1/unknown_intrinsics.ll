declare i8* @llvm.ptrmask.p0i8.i64(i8*, i64)
declare i32 @llvm.smax.i32(i32, i32)

define i8* @probe(i8* %p, i32 %a, i32 %b) {
entry:
  %masked = call i8* @llvm.ptrmask.p0i8.i64(i8* %p, i64 255)
  %v = call i32 @llvm.smax.i32(i32 %a, i32 %b)
  ret i8* %masked
}
