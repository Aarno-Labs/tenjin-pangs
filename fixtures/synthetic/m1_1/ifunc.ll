@IfuncTarget = ifunc void (), void ()* ()* @resolve

define void @target() {
entry:
  ret void
}

define void ()* @resolve() {
entry:
  ret void ()* @target
}

define void @ifunc_caller() {
entry:
  call void @IfuncTarget()
  ret void
}
