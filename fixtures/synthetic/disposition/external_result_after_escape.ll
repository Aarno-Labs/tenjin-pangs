; Soundness fixture: an external principal first learns @g's address, then a later result from
; the same external function is used as the address of a store. A finite ordinary-external row
; does not name @g, so every disposition certificate must still fail closed on @g's escape fact.

source_filename = "fixtures/synthetic/disposition/external_result_after_escape.c"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

@g = internal global i32 0, align 4, !dbg !0

declare i32* @external_exchange(i32*)

define i32 @main() !dbg !7 {
entry:
  call i32* @external_exchange(i32* @g), !dbg !11
  %p = call i32* @external_exchange(i32* null), !dbg !12
  store i32 1, i32* %p, align 4, !dbg !13
  ret i32 0, !dbg !14
}

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!5, !6}
!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "g", scope: !2, file: !3, line: 1, type: !4, isLocal: true, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !3, producer: "pangs-test", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, globals: !15)
!3 = !DIFile(filename: "fixtures/synthetic/disposition/external_result_after_escape.c", directory: ".")
!4 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!5 = !{i32 2, !"Dwarf Version", i32 4}
!6 = !{i32 2, !"Debug Info Version", i32 3}
!7 = distinct !DISubprogram(name: "main", scope: !3, file: !3, line: 5, type: !8, scopeLine: 5, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !10)
!8 = !DISubroutineType(types: !9)
!9 = !{!4}
!10 = !{}
!11 = !DILocation(line: 6, column: 3, scope: !7)
!12 = !DILocation(line: 7, column: 12, scope: !7)
!13 = !DILocation(line: 8, column: 3, scope: !7)
!14 = !DILocation(line: 9, column: 3, scope: !7)
!15 = !{!0}
