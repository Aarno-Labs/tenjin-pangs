; A guarded callback is always null. Steensgaard merges the two allocation
; addresses through @observe and supplies the spurious finite target @cb.
; Andersen removes it, then retains the finite base answer as explicit fallback.
; The global anchor keeps the callback initializer admitted, separating this
; target-lattice issue from internal_aggregate_callback_admission.ll.
%Pair = type { i8*, i8*, void ()* }
@keep = internal global void ()* @cb
define internal void @cb() { ret void }
define internal void @observe(%Pair* %p) { ret void }
define internal void @invoke_null(%Pair* %p) {
  %member = getelementptr %Pair, %Pair* %p, i64 0, i32 2
  %fp = load void ()*, void ()** %member
  %has = icmp ne void ()* %fp, null
  br i1 %has, label %call, label %done
call:
  call void %fp()
  br label %done
done:
  ret void
}
define i32 @main() {
  %a = alloca %Pair
  %b = alloca %Pair
  %am = getelementptr %Pair, %Pair* %a, i64 0, i32 2
  %bm = getelementptr %Pair, %Pair* %b, i64 0, i32 2
  store void ()* @cb, void ()** %am
  store void ()* null, void ()** %bm
  call void @observe(%Pair* %a)
  call void @observe(%Pair* %b)
  call void @invoke_null(%Pair* %b)
  ret i32 0
}
