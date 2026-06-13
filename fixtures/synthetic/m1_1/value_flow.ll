@P = global i8* null
@I = global i64 0

declare void @llvm.memcpy.p0i8.p0i8.i64(i8* nocapture writeonly, i8* nocapture readonly, i64, i1 immarg)

define i8* @flow(i1 %c, i8* %a, i8* %b) {
entry:
  %slot = alloca i8*
  store i8* %a, i8** %slot
  %loaded = load i8*, i8** %slot
  %gep = getelementptr i8, i8* %loaded, i64 0
  %cast = bitcast i8* %gep to i8*
  %sel = select i1 %c, i8* %cast, i8* %b
  br i1 %c, label %left, label %right
left:
  br label %join
right:
  br label %join
join:
  %phi = phi i8* [ %sel, %left ], [ %b, %right ]
  %fr = freeze i8* %phi
  %pi = ptrtoint i8* %fr to i64
  %ip = inttoptr i64 %pi to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* %ip, i8* %b, i64 4, i1 false)
  ret i8* %ip
}

define i64 @atomic_xchg(i64 %new) {
entry:
  %old = atomicrmw xchg i64* @I, i64 %new seq_cst
  ret i64 %old
}

define i8* @atomic_cas(i8* %expected, i8* %new) {
entry:
  %res = cmpxchg i8** @P, i8* %expected, i8* %new seq_cst seq_cst
  %old = extractvalue { i8*, i1 } %res, 0
  ret i8* %old
}
