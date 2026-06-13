@G = global i32 0
@GA = internal alias i32, i32* @G
@FnAlias = internal alias void (), void ()* @target

define void @target() {
entry:
  ret void
}

define void @caller() {
entry:
  %v = load i32, i32* @GA
  call void @FnAlias()
  ret void
}
