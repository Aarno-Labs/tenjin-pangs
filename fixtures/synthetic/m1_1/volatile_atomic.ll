@GP = global i8* null

define i8* @touch(i8* %p) {
entry:
  store volatile i8* %p, i8** @GP
  %v = load volatile i8*, i8** @GP
  store atomic i8* %p, i8** @GP seq_cst, align 8
  %a = load atomic i8*, i8** @GP seq_cst, align 8
  ret i8* %a
}
