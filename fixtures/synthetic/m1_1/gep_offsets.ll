%S = type { i8, i32, i8* }
%Inner = type { i16, i8* }
%Outer = type { i8, [3 x %Inner] }

define void @gep_offsets(%S* %s, [10 x i8]* %arr, %Outer* %outer, i64 %idx) {
entry:
  %field = getelementptr %S, %S* %s, i64 0, i32 2
  %elt = getelementptr [10 x i8], [10 x i8]* %arr, i64 0, i64 7
  %nested = getelementptr %Outer, %Outer* %outer, i64 0, i32 1, i64 2, i32 1
  %dyn = getelementptr [10 x i8], [10 x i8]* %arr, i64 0, i64 %idx
  ret void
}
