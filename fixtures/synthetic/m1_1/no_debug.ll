@GP = global i8* null

define void @callee(i8* %p) {
entry:
  store i8* %p, i8** @GP
  ret void
}

define void @driver(i8* %p) {
entry:
  call void @callee(i8* %p)
  store i8* %p, i8** @GP
  ret void
}
