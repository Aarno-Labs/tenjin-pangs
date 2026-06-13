declare i32 @may_throw()
declare i32 @__gxx_personality_v0(...)

define i32 @caller() personality i32 (...)* @__gxx_personality_v0 {
entry:
  %res = invoke i32 @may_throw() to label %ok unwind label %lpad

ok:
  ret i32 %res

lpad:
  %lp = landingpad { i8*, i32 }
          cleanup
  ret i32 0
}
