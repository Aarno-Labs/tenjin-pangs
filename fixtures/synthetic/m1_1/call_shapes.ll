declare i32 @id(i32)

@FP = global i32 (i32)* @id

define i32 @driver(i32 %x) {
entry:
  %fp = load i32 (i32)*, i32 (i32)** @FP
  %direct = call i32 @id(i32 %x)
  %indirect = call i32 %fp(i32 %direct)
  ret i32 %indirect
}
