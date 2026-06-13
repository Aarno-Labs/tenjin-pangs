@G = global i32 0
@FP = global void ()* @target
@FPCast = global i8* bitcast (void ()* @target to i8*)
@GPtr = global i32* @G
@Arr = global [4 x i8] zeroinitializer
@GepPtr = global i8* getelementptr ([4 x i8], [4 x i8]* @Arr, i64 0, i64 1)
@Table = global [2 x void ()*] [void ()* @target, void ()* @other]
%Record = type { i32, void ()* }
@Record = global %Record { i32 7, void ()* @target }

define void @target() {
entry:
  ret void
}

define void @other() {
entry:
  ret void
}
