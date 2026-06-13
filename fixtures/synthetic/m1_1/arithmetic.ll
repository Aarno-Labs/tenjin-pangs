define void @arith(i32 %a, i32 %b, float %x, float %y) {
entry:
  %sum = add i32 %a, %b
  %diff = sub i32 %a, %b
  %mask = and i32 %sum, %diff
  %cmp = icmp eq i32 %sum, %diff
  %fsum = fadd float %x, %y
  %neg = fneg float %x
  ret void
}
