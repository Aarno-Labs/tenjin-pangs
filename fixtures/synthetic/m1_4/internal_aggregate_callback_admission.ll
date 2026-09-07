; Regression: the helper's uncertified field load must admit the precise
; initializer component and refine to @cb without fallback. No external boundary.
; See 20260907_VIM_CALLBACK_ADMISSION_INVESTIGATION.md.
%Pair = type { i8*, i8*, void ()* }

define internal void @cb() { ret void }

define internal void @invoke(%Pair* %p) {
  %member = getelementptr %Pair, %Pair* %p, i64 0, i32 2
  %fp = load void ()*, void ()** %member
  call void %fp()
  ret void
}

define i32 @main() {
  %a = alloca %Pair
  %member = getelementptr %Pair, %Pair* %a, i64 0, i32 2
  store void ()* @cb, void ()** %member
  call void @invoke(%Pair* %a)
  ret i32 0
}
