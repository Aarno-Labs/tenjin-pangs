declare i32 @__gxx_personality_v0(...)
declare i32 @may_throw()

define void @caller() personality i32 (...)* @__gxx_personality_v0 {
entry:
  invoke i32 @may_throw() to label %ok unwind label %lpad

ok:
  ret void

lpad:
  %lp = landingpad { i8*, i32 }
          cleanup
  resume { i8*, i32 } %lp
}
