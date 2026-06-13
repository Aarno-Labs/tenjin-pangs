define i8* @casts(i8* %p) {
entry:
  %to_as1 = addrspacecast i8* %p to i8 addrspace(1)*
  %back = addrspacecast i8 addrspace(1)* %to_as1 to i8*
  ret i8* %back
}
