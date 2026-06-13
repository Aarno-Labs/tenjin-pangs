declare i32 @__gxx_personality_v0(...)
declare i32 @may_throw()

define i8* @agg_and_eh(i8* %p, i8* %q) personality i32 (...)* @__gxx_personality_v0 {
entry:
  %vec0 = insertelement <2 x i8*> poison, i8* %p, i64 0
  %vec1 = insertelement <2 x i8*> %vec0, i8* %q, i64 1
  %elt = extractelement <2 x i8*> %vec1, i64 0
  %agg0 = insertvalue { i8*, i32 } undef, i8* %p, 0
  %agg1 = insertvalue { i8*, i32 } %agg0, i32 7, 1
  %field = extractvalue { i8*, i32 } %agg1, 0
  invoke i32 @may_throw() to label %ok unwind label %lpad

ok:
  ret i8* %field

lpad:
  %lp = landingpad { i8*, i32 }
          cleanup
  %ehptr = extractvalue { i8*, i32 } %lp, 0
  ret i8* %ehptr
}
