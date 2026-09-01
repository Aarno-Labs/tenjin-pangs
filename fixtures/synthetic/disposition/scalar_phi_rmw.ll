source_filename = "scalar-phi-rmw.c"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

@g = global i32 0, align 4

define i32 @update(i1 %take_direct, i1 %continue) !dbg !4 {
entry:
  br i1 %take_direct, label %direct, label %increment

direct:
  %pre = load i32, i32* @g, align 4, !dbg !10
  br label %join

increment:
  %old = load i32, i32* @g, align 4, !dbg !11
  %first = add nsw i32 %old, 1, !dbg !11
  store i32 %first, i32* @g, align 4, !dbg !11
  br i1 %continue, label %through, label %exit

through:
  br label %join

join:
  %current = phi i32 [ %pre, %direct ], [ %first, %through ], !dbg !10
  %next = add nsw i32 %current, 1, !dbg !10
  store i32 %next, i32* @g, align 4, !dbg !10
  br label %exit

exit:
  %result = phi i32 [ %first, %increment ], [ %next, %join ]
  ret i32 %result
}

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!8, !9}
!0 = distinct !DICompileUnit(language: DW_LANG_C99, file: !1, producer: "pangs-test", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug)
!1 = !DIFile(filename: "scalar-phi-rmw.c", directory: "/tmp")
!2 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!3 = !DISubroutineType(types: !{!2, !2, !2})
!4 = distinct !DISubprogram(name: "update", scope: !1, file: !1, line: 1, type: !3, scopeLine: 1, spFlags: DISPFlagDefinition, unit: !0)
!8 = !{i32 2, !"Dwarf Version", i32 4}
!9 = !{i32 2, !"Debug Info Version", i32 3}
!10 = !DILocation(line: 10, column: 3, scope: !4)
!11 = !DILocation(line: 9, column: 3, scope: !4)
