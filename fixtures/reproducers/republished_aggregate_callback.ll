; Semantic counterpart of the PIR reproducer: foreign_use may overwrite field 1.
; The store/load round-trip preserves the runtime address, but defeats the solver's
; fixed exact-address certificate. Expected current differential exit: 3.
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%Pair = type { i8*, void ()* }
@aggregate = internal global %Pair zeroinitializer
@slot = internal global %Pair* null

declare void @foreign_use(%Pair*)

define internal void @cb() {
  ret void
}

define i32 @main() {
  %member = getelementptr %Pair, %Pair* @aggregate, i64 0, i32 1
  store void ()* @cb, void ()** %member
  store %Pair* @aggregate, %Pair** @slot
  %published = load %Pair*, %Pair** @slot
  call void @foreign_use(%Pair* %published)
  %shifted = getelementptr %Pair, %Pair* %published, i64 0, i32 1
  %callback = load void ()*, void ()** %shifted
  call void %callback()
  ret i32 0
}
