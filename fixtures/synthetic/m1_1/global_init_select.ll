@A = extern_weak global i8
@B = extern_weak global i8
@Sel = global i8* select (i1 icmp eq (i8* @A, i8* @B), i8* @A, i8* @B)
