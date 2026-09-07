; Soundness fixture: `&flag` is stored at a non-zero lane of a stack aggregate, the
; aggregate's base is republished through a global pointer, and a third function stores
; through `base + 1`. Both solver tiers must retain the shifted field target across that
; memory round trip. Pointer ModRef and the `written` fact must agree so the cascade
; cannot select `immutable` for a global that the program writes.

source_filename = "fixtures/synthetic/disposition/republished_aggregate_write.c"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

@flag = internal global i32 0, align 4, !dbg !0
@table = internal global i32** null, align 8, !dbg !16

define void @publish(i32** %o) !dbg !7 {
entry:
  store i32** %o, i32*** @table, align 8, !dbg !11
  ret void, !dbg !11
}

define void @write_through() !dbg !12 {
entry:
  %t = load i32**, i32*** @table, align 8, !dbg !13
  %e = getelementptr inbounds i32*, i32** %t, i32 1, !dbg !13
  %p = load i32*, i32** %e, align 8, !dbg !13
  store i32 1, i32* %p, align 4, !dbg !13
  ret void, !dbg !13
}

define i32 @main() !dbg !14 {
entry:
  %opts = alloca [3 x i32*], align 8
  %slot = getelementptr inbounds [3 x i32*], [3 x i32*]* %opts, i64 0, i64 1
  store i32* @flag, i32** %slot, align 8, !dbg !15
  %base = getelementptr inbounds [3 x i32*], [3 x i32*]* %opts, i64 0, i64 0
  call void @publish(i32** %base), !dbg !15
  call void @write_through(), !dbg !15
  %v = load i32, i32* @flag, align 4, !dbg !15
  ret i32 %v, !dbg !15
}

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!5, !6}
!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "flag", scope: !2, file: !3, line: 1, type: !4, isLocal: true, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !3, producer: "pangs-test", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, globals: !18)
!3 = !DIFile(filename: "fixtures/synthetic/disposition/republished_aggregate_write.c", directory: ".")
!4 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!5 = !{i32 2, !"Dwarf Version", i32 4}
!6 = !{i32 2, !"Debug Info Version", i32 3}
!7 = distinct !DISubprogram(name: "publish", scope: !3, file: !3, line: 4, type: !8, scopeLine: 4, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !10)
!8 = !DISubroutineType(types: !9)
!9 = !{null}
!10 = !{}
!11 = !DILocation(line: 5, column: 3, scope: !7)
!12 = distinct !DISubprogram(name: "write_through", scope: !3, file: !3, line: 8, type: !8, scopeLine: 8, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !10)
!13 = !DILocation(line: 9, column: 3, scope: !12)
!14 = distinct !DISubprogram(name: "main", scope: !3, file: !3, line: 12, type: !8, scopeLine: 12, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !10)
!15 = !DILocation(line: 13, column: 3, scope: !14)
!16 = !DIGlobalVariableExpression(var: !17, expr: !DIExpression())
!17 = distinct !DIGlobalVariable(name: "table", scope: !2, file: !3, line: 2, type: !4, isLocal: true, isDefinition: true)
!18 = !{!0, !16}
