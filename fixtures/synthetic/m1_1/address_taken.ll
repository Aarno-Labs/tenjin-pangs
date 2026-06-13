declare void @accept_cb(void ()*)
declare void @accept_vararg(i32, ...)

define void @cb_arg() {
entry:
  ret void
}

define void @cb_vararg() {
entry:
  ret void
}

define void @cb_store() {
entry:
  ret void
}

define void @driver() {
entry:
  %slot = alloca void ()*
  call void @accept_cb(void ()* @cb_arg)
  call void (i32, ...) @accept_vararg(i32 7, void ()* @cb_vararg)
  store void ()* @cb_store, void ()** %slot
  ret void
}
