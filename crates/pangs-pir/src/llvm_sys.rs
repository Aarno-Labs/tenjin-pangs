use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;
use std::ptr;

#[allow(deprecated)]
use llvm_sys::bit_reader::LLVMParseBitcodeInContext;
use llvm_sys::core::*;
use llvm_sys::ir_reader::LLVMParseIRInContext;
use llvm_sys::prelude::*;
use llvm_sys::target::{
    LLVMABISizeOfType, LLVMGetModuleDataLayout, LLVMOffsetOfElement, LLVMTargetDataRef,
};
use llvm_sys::{LLVMDLLStorageClass, LLVMLinkage, LLVMOpcode, LLVMTypeKind, LLVMVisibility};

use crate::{
    AbiClass, Access, Func, Global, Loc, LoweringStats, Param, Pir, PirError, Signature, Stmt,
};

pub fn lower_path(path: &Path) -> Result<Pir, PirError> {
    let module = ParsedModule::from_path(path)?;
    Ok(unsafe { lower_module(module.module) })
}

struct ParsedModule {
    context: LLVMContextRef,
    module: LLVMModuleRef,
}

impl ParsedModule {
    #[allow(deprecated)]
    fn from_path(path: &Path) -> Result<Self, PirError> {
        let path_str = path.display().to_string();
        let c_path = CString::new(path_str.clone()).map_err(|_| PirError::Llvm {
            path: path_str.clone(),
            message: "path contains interior NUL".to_string(),
        })?;
        unsafe {
            let context = LLVMContextCreate();
            LLVMContextSetDiscardValueNames(context, 0);

            let mut buffer = ptr::null_mut();
            let mut message = ptr::null_mut();
            let rc = LLVMCreateMemoryBufferWithContentsOfFile(
                c_path.as_ptr(),
                &mut buffer,
                &mut message,
            );
            if rc != 0 {
                let message = take_message(message);
                LLVMContextDispose(context);
                return Err(PirError::Llvm {
                    path: path_str,
                    message,
                });
            }

            let mut module = ptr::null_mut();
            let parse_rc = match path.extension().and_then(|ext| ext.to_str()) {
                Some("bc") => LLVMParseBitcodeInContext(context, buffer, &mut module, &mut message),
                Some("ll") => LLVMParseIRInContext(context, buffer, &mut module, &mut message),
                _ => unreachable!("caller filters extensions"),
            };

            if parse_rc != 0 {
                let message = take_message(message);
                LLVMContextDispose(context);
                return Err(PirError::Llvm {
                    path: path.display().to_string(),
                    message,
                });
            }

            Ok(Self { context, module })
        }
    }
}

impl Drop for ParsedModule {
    fn drop(&mut self) {
        unsafe {
            if !self.module.is_null() {
                LLVMDisposeModule(self.module);
            }
            if !self.context.is_null() {
                LLVMContextDispose(self.context);
            }
        }
    }
}

struct ModuleCtx {
    data_layout: LLVMTargetDataRef,
    func_names: BTreeSet<String>,
    global_names: BTreeSet<String>,
}

struct FunctionCtx {
    func_name: String,
    unnamed: BTreeMap<usize, String>,
    next_unnamed: u64,
}

impl FunctionCtx {
    fn new(func_name: String) -> Self {
        Self {
            func_name,
            unnamed: BTreeMap::new(),
            next_unnamed: 0,
        }
    }

    unsafe fn local_key(&mut self, value: LLVMValueRef) -> String {
        let name = value_name(value);
        if !name.is_empty() {
            return format!("%{}::{name}", self.func_name);
        }
        let key = value as usize;
        if let Some(existing) = self.unnamed.get(&key) {
            return existing.clone();
        }
        let generated = format!("%{}::tmp{}", self.func_name, self.next_unnamed);
        self.next_unnamed += 1;
        self.unnamed.insert(key, generated.clone());
        generated
    }

    unsafe fn operand_key(&mut self, value: LLVMValueRef) -> String {
        if !LLVMIsAFunction(value).is_null()
            || !LLVMIsAGlobalVariable(value).is_null()
            || !LLVMIsAGlobalAlias(value).is_null()
            || !LLVMIsAGlobalIFunc(value).is_null()
        {
            return format!("@{}", value_name(value));
        }
        if !LLVMIsAArgument(value).is_null() || !LLVMIsAInstruction(value).is_null() {
            return self.local_key(value);
        }
        if !LLVMIsAConstantInt(value).is_null() {
            return LLVMConstIntGetSExtValue(value).to_string();
        }
        if !LLVMIsAConstantPointerNull(value).is_null() {
            return "null".to_string();
        }
        if !LLVMIsAUndefValue(value).is_null() {
            return "undef".to_string();
        }
        if !LLVMIsAPoisonValue(value).is_null() {
            return "poison".to_string();
        }
        value_string(value)
    }
}

unsafe fn lower_module(module: LLVMModuleRef) -> Pir {
    let functions = collect_functions(module);
    let globals = collect_globals(module);
    let aliases = collect_aliases(module);
    let ifuncs = collect_ifuncs(module);

    let func_names = functions
        .iter()
        .map(|func| value_name(*func))
        .filter(|name| !is_skipped_intrinsic(name))
        .collect::<BTreeSet<_>>();
    let global_names = globals
        .iter()
        .map(|global| value_name(*global))
        .collect::<BTreeSet<_>>();
    let ctx = ModuleCtx {
        data_layout: LLVMGetModuleDataLayout(module),
        func_names,
        global_names,
    };

    let mut lowering = LoweringStats {
        functions: functions
            .iter()
            .filter(|func| {
                !is_skipped_intrinsic(&value_name(**func)) && LLVMIsDeclaration(**func) == 0
            })
            .count() as u64,
        declarations: functions
            .iter()
            .filter(|func| {
                !is_skipped_intrinsic(&value_name(**func)) && LLVMIsDeclaration(**func) != 0
            })
            .count() as u64,
        globals: globals.len() as u64,
        aliases: aliases.len() as u64,
        ifuncs: ifuncs.len() as u64,
        ..LoweringStats::default()
    };

    let address_taken = collect_address_taken(&ctx, &globals);

    let mut pir_functions = Vec::new();
    for function in functions {
        let name = value_name(function);
        if is_skipped_intrinsic(&name) {
            continue;
        }
        if LLVMIsDeclaration(function) != 0 {
            pir_functions.push(lower_decl(&ctx, function, &address_taken, &mut lowering));
        } else {
            pir_functions.push(lower_function(
                &ctx,
                function,
                &address_taken,
                &mut lowering,
            ));
        }
    }

    let pir_globals = globals
        .iter()
        .map(|global| {
            lowering.bump_missing_debug_location("global");
            Global {
                key: value_name(*global),
                file: None,
                line: None,
                is_const: LLVMIsGlobalConstant(*global) != 0,
                mutable: LLVMIsGlobalConstant(*global) == 0,
                exported: is_exported(
                    LLVMGetLinkage(*global),
                    LLVMGetVisibility(*global),
                    LLVMGetDLLStorageClass(*global),
                ),
            }
        })
        .collect::<Vec<_>>();
    let global_init = lower_global_initializers(&ctx, &globals, &mut lowering);

    Pir {
        module: module_identifier(module),
        source: Some(module_source_file(module)),
        lowering,
        functions: pir_functions,
        globals: pir_globals,
        global_init,
    }
}

unsafe fn lower_function(
    ctx: &ModuleCtx,
    function: LLVMValueRef,
    address_taken: &BTreeSet<String>,
    lowering: &mut LoweringStats,
) -> Func {
    lowering.bump_missing_debug_location("function");
    let key = value_name(function);
    let mut body = Vec::new();
    let mut fctx = FunctionCtx::new(key.clone());

    let mut block = LLVMGetFirstBasicBlock(function);
    while !block.is_null() {
        let mut inst = LLVMGetFirstInstruction(block);
        while !inst.is_null() {
            let opcode = LLVMGetInstructionOpcode(inst);
            lowering.bump_instruction(opcode_key(opcode));
            lower_instruction(ctx, &mut fctx, inst, opcode, &mut body, lowering);
            inst = LLVMGetNextInstruction(inst);
        }
        block = LLVMGetNextBasicBlock(block);
    }

    Func {
        key: key.clone(),
        sig: function_signature(ctx, function, lowering),
        file: None,
        line: None,
        external: false,
        exported: is_exported(
            LLVMGetLinkage(function),
            LLVMGetVisibility(function),
            LLVMGetDLLStorageClass(function),
        ),
        address_taken: address_taken.contains(&key),
        body,
    }
}

unsafe fn lower_decl(
    ctx: &ModuleCtx,
    function: LLVMValueRef,
    address_taken: &BTreeSet<String>,
    lowering: &mut LoweringStats,
) -> Func {
    lowering.bump_missing_debug_location("declaration");
    let key = value_name(function);
    Func {
        key: key.clone(),
        sig: function_signature(ctx, function, lowering),
        file: None,
        line: None,
        external: true,
        exported: is_exported(
            LLVMGetLinkage(function),
            LLVMGetVisibility(function),
            LLVMGetDLLStorageClass(function),
        ),
        address_taken: address_taken.contains(&key),
        body: Vec::new(),
    }
}

unsafe fn lower_instruction(
    ctx: &ModuleCtx,
    fctx: &mut FunctionCtx,
    inst: LLVMValueRef,
    opcode: LLVMOpcode,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    match opcode {
        LLVMOpcode::LLVMAlloca => {
            body.push(Stmt::Alloca {
                dest: fctx.local_key(inst),
                ty: type_string(LLVMGetAllocatedType(inst)),
                loc: loc(inst),
            });
            lowering.bump_modeled("alloca");
            bump_missing_loc(lowering, "alloca", inst);
        }
        LLVMOpcode::LLVMLoad => {
            let address = LLVMGetOperand(inst, 0);
            body.push(Stmt::Load {
                dest: fctx.local_key(inst),
                address: fctx.operand_key(address),
                loc: loc(inst),
            });
            lowering.bump_modeled("load");
            bump_missing_loc(lowering, "load", inst);
            if let Some(global) =
                operand_global_name(address).filter(|name| ctx.global_names.contains(name))
            {
                body.push(Stmt::GlobalRef {
                    global,
                    access: Access::Ref,
                    loc: loc(inst),
                });
                lowering.bump_modeled("global_ref");
            }
        }
        LLVMOpcode::LLVMStore => {
            let value = LLVMGetOperand(inst, 0);
            let address = LLVMGetOperand(inst, 1);
            body.push(Stmt::Store {
                address: fctx.operand_key(address),
                value: fctx.operand_key(value),
                loc: loc(inst),
            });
            lowering.bump_modeled("store");
            bump_missing_loc(lowering, "store", inst);
            if let Some(global) =
                operand_global_name(address).filter(|name| ctx.global_names.contains(name))
            {
                body.push(Stmt::GlobalRef {
                    global,
                    access: Access::Mod,
                    loc: loc(inst),
                });
                lowering.bump_modeled("global_mod");
            }
        }
        LLVMOpcode::LLVMGetElementPtr => {
            let base = LLVMGetOperand(inst, 0);
            body.push(Stmt::Gep {
                dest: fctx.local_key(inst),
                base: fctx.operand_key(base),
                byte_off: gep_byte_offset(ctx, inst, lowering),
                loc: loc(inst),
            });
            lowering.bump_modeled("gep");
            bump_missing_loc(lowering, "gep", inst);
        }
        LLVMOpcode::LLVMBitCast | LLVMOpcode::LLVMAddrSpaceCast => {
            let source = LLVMGetOperand(inst, 0);
            if is_pointer_like_type(LLVMTypeOf(source)) || is_pointer_like_type(LLVMTypeOf(inst)) {
                body.push(Stmt::Assign {
                    dest: fctx.local_key(inst),
                    sources: vec![fctx.operand_key(source)],
                    loc: loc(inst),
                });
                lowering.bump_modeled("assign");
            } else {
                lowering.bump_skipped(match opcode {
                    LLVMOpcode::LLVMBitCast => "bitcast_non_pointer",
                    _ => "addrspacecast_non_pointer",
                });
            }
            bump_missing_loc(
                lowering,
                match opcode {
                    LLVMOpcode::LLVMBitCast => "bitcast",
                    _ => "addrspacecast",
                },
                inst,
            );
        }
        LLVMOpcode::LLVMPtrToInt => {
            let source = LLVMGetOperand(inst, 0);
            body.push(Stmt::PtrToInt {
                dest: fctx.local_key(inst),
                source: fctx.operand_key(source),
                loc: loc(inst),
            });
            lowering.bump_modeled("ptrtoint");
            bump_missing_loc(lowering, "ptrtoint", inst);
        }
        LLVMOpcode::LLVMIntToPtr => {
            let source = LLVMGetOperand(inst, 0);
            body.push(Stmt::IntToPtr {
                dest: fctx.local_key(inst),
                source: fctx.operand_key(source),
                loc: loc(inst),
            });
            lowering.bump_modeled("inttoptr");
            lowering.bump_tainted("inttoptr");
            bump_missing_loc(lowering, "inttoptr", inst);
        }
        LLVMOpcode::LLVMCall => lower_call(ctx, fctx, inst, body, lowering),
        LLVMOpcode::LLVMRet => {
            let value = if LLVMGetNumOperands(inst) == 0 {
                None
            } else {
                Some(fctx.operand_key(LLVMGetOperand(inst, 0)))
            };
            body.push(Stmt::Return {
                value,
                loc: loc(inst),
            });
            lowering.bump_modeled("return");
            bump_missing_loc(lowering, "return", inst);
        }
        _ => lowering.bump_skipped(format!("unmodeled_instruction:{}", opcode_key(opcode))),
    }
}

unsafe fn lower_call(
    ctx: &ModuleCtx,
    fctx: &mut FunctionCtx,
    inst: LLVMValueRef,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    let called = LLVMGetCalledValue(inst);
    if !LLVMIsAInlineAsm(called).is_null() {
        lowering.bump_tainted("inline_asm_call");
        push_unknown(
            body,
            "call",
            call_operand_keys(fctx, inst),
            call_result_keys(fctx, inst),
            "inline_asm_call",
            loc(inst),
            lowering,
        );
        return;
    }

    if let Some(callee) = direct_callee_name(called) {
        if callee.starts_with("llvm.dbg.") {
            lowering.bump_skipped("dbg_intrinsic");
            return;
        }
        if callee.starts_with("llvm.") {
            lowering.bump_skipped(format!("intrinsic:{callee}"));
            return;
        }
        body.push(Stmt::CallDirect {
            callee,
            sig: call_signature(ctx, inst, lowering),
            loc: loc(inst),
        });
        lowering.bump_modeled("call_direct");
    } else {
        body.push(Stmt::CallIndirect {
            operand: fctx.operand_key(called),
            sig: call_signature(ctx, inst, lowering),
            loc: loc(inst),
        });
        lowering.bump_modeled("call_indirect");
    }
    bump_missing_loc(lowering, "call", inst);
}

unsafe fn lower_global_initializers(
    ctx: &ModuleCtx,
    globals: &[LLVMValueRef],
    lowering: &mut LoweringStats,
) -> Vec<Stmt> {
    let mut body = Vec::new();
    let mut temp_ordinal = 0_u64;

    for global in globals {
        let initializer = LLVMGetInitializer(*global);
        if initializer.is_null() {
            continue;
        }
        let key = value_name(*global);
        body.push(Stmt::GlobalRef {
            global: key.clone(),
            access: Access::Mod,
            loc: None,
        });
        lowering.bump_modeled("global_init_mod");
        if !lower_global_initializer_value(
            ctx,
            &format!("@{key}"),
            initializer,
            &mut body,
            &mut temp_ordinal,
            lowering,
        ) {
            lowering.bump_skipped("global_initializer_non_pointer");
        }
    }

    body
}

unsafe fn lower_global_initializer_value(
    ctx: &ModuleCtx,
    address: &str,
    constant: LLVMValueRef,
    body: &mut Vec<Stmt>,
    temp_ordinal: &mut u64,
    lowering: &mut LoweringStats,
) -> bool {
    if !LLVMIsAConstantStruct(constant).is_null() {
        let mut found = false;
        let count = LLVMGetNumOperands(constant);
        for index in 0..count {
            let field_address = struct_field_address(
                ctx,
                address,
                LLVMTypeOf(constant),
                index as usize,
                body,
                temp_ordinal,
                lowering,
            );
            found |= lower_global_initializer_value(
                ctx,
                &field_address,
                LLVMGetOperand(constant, index as u32),
                body,
                temp_ordinal,
                lowering,
            );
        }
        return found;
    }
    if !LLVMIsAConstantArray(constant).is_null()
        || !LLVMIsAConstantDataArray(constant).is_null()
        || !LLVMIsAConstantVector(constant).is_null()
        || !LLVMIsAConstantDataVector(constant).is_null()
    {
        let mut found = false;
        let count = LLVMGetNumOperands(constant);
        let element_type = LLVMGetElementType(LLVMTypeOf(constant));
        for index in 0..count {
            let field_address = sequential_element_address(
                ctx,
                address,
                element_type,
                index as usize,
                body,
                temp_ordinal,
                lowering,
            );
            found |= lower_global_initializer_value(
                ctx,
                &field_address,
                LLVMGetOperand(constant, index as u32),
                body,
                temp_ordinal,
                lowering,
            );
        }
        return found;
    }
    if constant_has_pointer_flow(constant) {
        let value = lower_constant_expr_value(ctx, constant, body, temp_ordinal, lowering);
        body.push(Stmt::Store {
            address: address.to_string(),
            value: value.clone(),
            loc: None,
        });
        lowering.bump_modeled("global_init_store");
        if let Some(global) =
            operand_global_name(constant).filter(|name| ctx.global_names.contains(name))
        {
            body.push(Stmt::GlobalRef {
                global,
                access: Access::Ref,
                loc: None,
            });
            lowering.bump_modeled("global_init_ref");
        }
        return true;
    }
    false
}

unsafe fn lower_constant_expr_value(
    ctx: &ModuleCtx,
    constant: LLVMValueRef,
    body: &mut Vec<Stmt>,
    temp_ordinal: &mut u64,
    lowering: &mut LoweringStats,
) -> String {
    if !LLVMIsAFunction(constant).is_null()
        || !LLVMIsAGlobalVariable(constant).is_null()
        || !LLVMIsAGlobalAlias(constant).is_null()
        || !LLVMIsAGlobalIFunc(constant).is_null()
    {
        return format!("@{}", value_name(constant));
    }
    if !LLVMIsAConstantExpr(constant).is_null() {
        match LLVMGetConstOpcode(constant) {
            LLVMOpcode::LLVMBitCast | LLVMOpcode::LLVMAddrSpaceCast => {
                let source = lower_constant_expr_value(
                    ctx,
                    LLVMGetOperand(constant, 0),
                    body,
                    temp_ordinal,
                    lowering,
                );
                let dest = global_init_temp(temp_ordinal);
                body.push(Stmt::Assign {
                    dest: dest.clone(),
                    sources: vec![source],
                    loc: None,
                });
                lowering.bump_modeled("global_init_assign");
                dest
            }
            LLVMOpcode::LLVMGetElementPtr => {
                let base = lower_constant_expr_value(
                    ctx,
                    LLVMGetOperand(constant, 0),
                    body,
                    temp_ordinal,
                    lowering,
                );
                let dest = global_init_temp(temp_ordinal);
                body.push(Stmt::Gep {
                    dest: dest.clone(),
                    base,
                    byte_off: constant_gep_byte_offset(ctx, constant, lowering),
                    loc: None,
                });
                lowering.bump_modeled("global_init_gep");
                dest
            }
            LLVMOpcode::LLVMPtrToInt => {
                let source = lower_constant_expr_value(
                    ctx,
                    LLVMGetOperand(constant, 0),
                    body,
                    temp_ordinal,
                    lowering,
                );
                let dest = global_init_temp(temp_ordinal);
                body.push(Stmt::PtrToInt {
                    dest: dest.clone(),
                    source,
                    loc: None,
                });
                lowering.bump_modeled("global_init_ptrtoint");
                lowering.bump_tainted("global_initializer_ptrtoint");
                dest
            }
            LLVMOpcode::LLVMIntToPtr => {
                let source = value_string(LLVMGetOperand(constant, 0));
                let dest = global_init_temp(temp_ordinal);
                body.push(Stmt::IntToPtr {
                    dest: dest.clone(),
                    source,
                    loc: None,
                });
                lowering.bump_modeled("global_init_inttoptr");
                lowering.bump_tainted("global_initializer_inttoptr");
                dest
            }
            other => {
                let dest = global_init_temp(temp_ordinal);
                lowering.bump_tainted(format!(
                    "global_initializer_unmodeled_pointer_constant:{}",
                    opcode_key(other)
                ));
                push_unknown(
                    body,
                    format!("constant_expr:{}", opcode_key(other)),
                    constant_pointer_operand_keys(constant),
                    vec![dest.clone()],
                    "global_initializer_pointer_constant",
                    None,
                    lowering,
                );
                dest
            }
        }
    } else {
        let dest = global_init_temp(temp_ordinal);
        lowering.bump_tainted("global_initializer_unmodeled_pointer_constant:constant");
        push_unknown(
            body,
            "constant_expr:constant",
            constant_pointer_operand_keys(constant),
            vec![dest.clone()],
            "global_initializer_pointer_constant",
            None,
            lowering,
        );
        dest
    }
}

unsafe fn collect_address_taken(ctx: &ModuleCtx, globals: &[LLVMValueRef]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for global in globals {
        let initializer = LLVMGetInitializer(*global);
        if !initializer.is_null() {
            collect_constant_func_refs(ctx, initializer, &mut out);
        }
    }
    out
}

unsafe fn collect_constant_func_refs(
    ctx: &ModuleCtx,
    constant: LLVMValueRef,
    out: &mut BTreeSet<String>,
) {
    if let Some(name) = direct_callee_name(constant) {
        if ctx.func_names.contains(&name) {
            out.insert(name);
        }
        return;
    }
    if !LLVMIsAConstantStruct(constant).is_null()
        || !LLVMIsAConstantArray(constant).is_null()
        || !LLVMIsAConstantVector(constant).is_null()
        || !LLVMIsAConstantDataArray(constant).is_null()
        || !LLVMIsAConstantDataVector(constant).is_null()
        || !LLVMIsAConstantExpr(constant).is_null()
    {
        let count = LLVMGetNumOperands(constant);
        for index in 0..count {
            collect_constant_func_refs(ctx, LLVMGetOperand(constant, index as u32), out);
        }
    }
}

unsafe fn function_signature(
    ctx: &ModuleCtx,
    function: LLVMValueRef,
    lowering: &mut LoweringStats,
) -> Signature {
    let function_ty = LLVMGetElementType(LLVMTypeOf(function));
    let cc = cc_key(LLVMGetFunctionCallConv(function), lowering);
    Signature {
        ret: abi_class(LLVMGetReturnType(function_ty)),
        params: param_types(function_ty)
            .into_iter()
            .enumerate()
            .map(|(index, ty)| function_param_class(ctx, function, index as u32 + 1, ty))
            .collect(),
        vararg: LLVMIsFunctionVarArg(function_ty) != 0,
        cc,
    }
}

unsafe fn call_signature(
    ctx: &ModuleCtx,
    inst: LLVMValueRef,
    lowering: &mut LoweringStats,
) -> Signature {
    let function_ty = LLVMGetCalledFunctionType(inst);
    let cc = cc_key(LLVMGetInstructionCallConv(inst), lowering);
    Signature {
        ret: abi_class(LLVMGetReturnType(function_ty)),
        params: param_types(function_ty)
            .into_iter()
            .enumerate()
            .map(|(index, ty)| callsite_param_class(ctx, inst, index as u32 + 1, ty))
            .collect(),
        vararg: LLVMIsFunctionVarArg(function_ty) != 0,
        cc,
    }
}

unsafe fn function_param_class(
    ctx: &ModuleCtx,
    function: LLVMValueRef,
    index: u32,
    ty: LLVMTypeRef,
) -> Param {
    param_class_with_attrs(
        ty,
        collect_attrs(
            |dest| LLVMGetAttributesAtIndex(function, index, dest),
            LLVMGetAttributeCountAtIndex(function, index),
        ),
        ctx.data_layout,
    )
}

unsafe fn callsite_param_class(
    ctx: &ModuleCtx,
    inst: LLVMValueRef,
    index: u32,
    ty: LLVMTypeRef,
) -> Param {
    param_class_with_attrs(
        ty,
        collect_attrs(
            |dest| LLVMGetCallSiteAttributes(inst, index, dest),
            LLVMGetCallSiteAttributeCount(inst, index),
        ),
        ctx.data_layout,
    )
}

unsafe fn collect_attrs<F>(fill: F, count: u32) -> Vec<LLVMAttributeRef>
where
    F: FnOnce(*mut LLVMAttributeRef),
{
    if count == 0 {
        return Vec::new();
    }
    let mut attrs = vec![ptr::null_mut(); count as usize];
    fill(attrs.as_mut_ptr());
    attrs
}

unsafe fn param_class_with_attrs(
    ty: LLVMTypeRef,
    attrs: Vec<LLVMAttributeRef>,
    data_layout: LLVMTargetDataRef,
) -> Param {
    let byval_kind = enum_attribute_kind("byval");
    let sret_kind = enum_attribute_kind("sret");
    for attr in attrs {
        if LLVMIsTypeAttribute(attr) == 0 {
            continue;
        }
        let kind = LLVMGetEnumAttributeKind(attr);
        if kind == byval_kind {
            return Param::Byval {
                size: type_size_key(data_layout, LLVMGetTypeAttributeValue(attr)),
            };
        }
        if kind == sret_kind {
            return Param::Sret {
                size: type_size_key(data_layout, LLVMGetTypeAttributeValue(attr)),
            };
        }
    }

    match abi_class(ty) {
        AbiClass::Integer => Param::Integer,
        AbiClass::Sse => Param::Sse,
        AbiClass::X87 => Param::X87,
        AbiClass::Fp128 => Param::Fp128,
        AbiClass::Void => Param::Void,
        AbiClass::Byval { size } => Param::Byval { size },
        AbiClass::Sret { size } => Param::Sret { size },
    }
}

unsafe fn enum_attribute_kind(name: &str) -> u32 {
    LLVMGetEnumAttributeKindForName(name.as_ptr().cast(), name.len())
}

unsafe fn param_types(function_ty: LLVMTypeRef) -> Vec<LLVMTypeRef> {
    let count = LLVMCountParamTypes(function_ty);
    if count == 0 {
        return Vec::new();
    }
    let mut params = vec![ptr::null_mut(); count as usize];
    LLVMGetParamTypes(function_ty, params.as_mut_ptr());
    params
}

unsafe fn abi_class(ty: LLVMTypeRef) -> AbiClass {
    match LLVMGetTypeKind(ty) {
        LLVMTypeKind::LLVMVoidTypeKind => AbiClass::Void,
        LLVMTypeKind::LLVMIntegerTypeKind => AbiClass::Integer,
        LLVMTypeKind::LLVMPointerTypeKind => AbiClass::Integer,
        LLVMTypeKind::LLVMFloatTypeKind | LLVMTypeKind::LLVMDoubleTypeKind => AbiClass::Sse,
        LLVMTypeKind::LLVMX86_FP80TypeKind => AbiClass::X87,
        LLVMTypeKind::LLVMFP128TypeKind | LLVMTypeKind::LLVMPPC_FP128TypeKind => AbiClass::Fp128,
        _ => AbiClass::Integer,
    }
}

unsafe fn type_size_key(data_layout: LLVMTargetDataRef, ty: LLVMTypeRef) -> u64 {
    match LLVMGetTypeKind(ty) {
        LLVMTypeKind::LLVMVoidTypeKind
        | LLVMTypeKind::LLVMFunctionTypeKind
        | LLVMTypeKind::LLVMLabelTypeKind
        | LLVMTypeKind::LLVMMetadataTypeKind
        | LLVMTypeKind::LLVMTokenTypeKind
        | LLVMTypeKind::LLVMX86_AMXTypeKind => 0,
        _ => LLVMABISizeOfType(data_layout, ty),
    }
}

unsafe fn gep_byte_offset(
    ctx: &ModuleCtx,
    inst: LLVMValueRef,
    lowering: &mut LoweringStats,
) -> Option<i64> {
    let operand_count = LLVMGetNumOperands(inst);
    let mut indices = Vec::new();
    for index in 1..operand_count {
        let operand = LLVMGetOperand(inst, index as u32);
        let Some(value) = constant_i64(operand) else {
            lowering.bump_skipped("gep_dynamic_index");
            return None;
        };
        indices.push(value);
    }
    let result = gep_offset_from_indices(ctx, LLVMGetGEPSourceElementType(inst), &indices);
    if result.is_some() {
        lowering.bump_modeled("gep_byte_offset");
    } else {
        lowering.bump_skipped("gep_unsupported_offset");
    }
    result
}

unsafe fn constant_gep_byte_offset(
    ctx: &ModuleCtx,
    constant: LLVMValueRef,
    lowering: &mut LoweringStats,
) -> Option<i64> {
    let operand_count = LLVMGetNumOperands(constant);
    if operand_count == 0 {
        lowering.bump_skipped("constant_gep_non_pointer_base");
        return None;
    }
    let mut indices = Vec::new();
    for index in 1..operand_count {
        let operand = LLVMGetOperand(constant, index as u32);
        let Some(value) = constant_i64(operand) else {
            lowering.bump_skipped("constant_gep_dynamic_index");
            return None;
        };
        indices.push(value);
    }
    let result = gep_offset_from_indices(ctx, LLVMGetGEPSourceElementType(constant), &indices);
    if result.is_some() {
        lowering.bump_modeled("global_init_gep_byte_offset");
    } else {
        lowering.bump_skipped("constant_gep_unsupported_offset");
    }
    result
}

unsafe fn gep_offset_from_indices(
    ctx: &ModuleCtx,
    source_element_type: LLVMTypeRef,
    indices: &[i64],
) -> Option<i64> {
    let (first, rest) = indices.split_first()?;
    let mut current = source_element_type;
    let mut total = i128::from(*first).checked_mul(i128::from(type_size_key(
        ctx.data_layout,
        source_element_type,
    )))?;

    for index in rest {
        match LLVMGetTypeKind(current) {
            LLVMTypeKind::LLVMStructTypeKind => {
                let element = u32::try_from(*index).ok()?;
                total = total.checked_add(i128::from(LLVMOffsetOfElement(
                    ctx.data_layout,
                    current,
                    element,
                )))?;
                current = struct_element_type(current, element)?;
            }
            LLVMTypeKind::LLVMArrayTypeKind
            | LLVMTypeKind::LLVMPointerTypeKind
            | LLVMTypeKind::LLVMVectorTypeKind => {
                let element_type = LLVMGetElementType(current);
                total = total.checked_add(
                    i128::from(*index)
                        .checked_mul(i128::from(type_size_key(ctx.data_layout, element_type)))?,
                )?;
                current = element_type;
            }
            _ => return None,
        }
    }

    i64::try_from(total).ok()
}

unsafe fn struct_field_address(
    ctx: &ModuleCtx,
    base: &str,
    struct_type: LLVMTypeRef,
    index: usize,
    body: &mut Vec<Stmt>,
    temp_ordinal: &mut u64,
    lowering: &mut LoweringStats,
) -> String {
    let byte_off = u32::try_from(index)
        .ok()
        .map(|field| LLVMOffsetOfElement(ctx.data_layout, struct_type, field))
        .and_then(|offset| i64::try_from(offset).ok());
    global_init_element_address(base, byte_off, body, temp_ordinal, lowering)
}

unsafe fn sequential_element_address(
    ctx: &ModuleCtx,
    base: &str,
    element_type: LLVMTypeRef,
    index: usize,
    body: &mut Vec<Stmt>,
    temp_ordinal: &mut u64,
    lowering: &mut LoweringStats,
) -> String {
    let byte_off = i128::from(type_size_key(ctx.data_layout, element_type))
        .checked_mul(i128::try_from(index).ok().unwrap_or_default())
        .and_then(|offset| i64::try_from(offset).ok());
    global_init_element_address(base, byte_off, body, temp_ordinal, lowering)
}

fn global_init_element_address(
    base: &str,
    byte_off: Option<i64>,
    body: &mut Vec<Stmt>,
    temp_ordinal: &mut u64,
    lowering: &mut LoweringStats,
) -> String {
    match byte_off {
        Some(0) => base.to_string(),
        Some(byte_off) => {
            let dest = global_init_temp(temp_ordinal);
            body.push(Stmt::Gep {
                dest: dest.clone(),
                base: base.to_string(),
                byte_off: Some(byte_off),
                loc: None,
            });
            lowering.bump_modeled("global_init_field_gep");
            dest
        }
        None => {
            lowering.bump_skipped("global_init_aggregate_unknown_offset");
            base.to_string()
        }
    }
}

unsafe fn struct_element_type(struct_ty: LLVMTypeRef, index: u32) -> Option<LLVMTypeRef> {
    let count = LLVMCountStructElementTypes(struct_ty);
    if index >= count {
        return None;
    }
    let mut elements = vec![ptr::null_mut(); count as usize];
    LLVMGetStructElementTypes(struct_ty, elements.as_mut_ptr());
    Some(elements[index as usize])
}

unsafe fn constant_has_pointer_flow(constant: LLVMValueRef) -> bool {
    if !LLVMIsAConstantPointerNull(constant).is_null()
        || !LLVMIsAConstantAggregateZero(constant).is_null()
        || !LLVMIsAUndefValue(constant).is_null()
        || !LLVMIsAPoisonValue(constant).is_null()
    {
        return false;
    }
    if !LLVMIsAFunction(constant).is_null()
        || !LLVMIsAGlobalVariable(constant).is_null()
        || !LLVMIsAGlobalAlias(constant).is_null()
        || !LLVMIsAGlobalIFunc(constant).is_null()
    {
        return true;
    }
    if !LLVMIsAConstantExpr(constant).is_null() {
        return match LLVMGetConstOpcode(constant) {
            LLVMOpcode::LLVMGetElementPtr | LLVMOpcode::LLVMIntToPtr => true,
            _ => {
                let count = LLVMGetNumOperands(constant);
                (0..count)
                    .any(|index| constant_has_pointer_flow(LLVMGetOperand(constant, index as u32)))
                    || is_pointer_like_type(LLVMTypeOf(constant))
            }
        };
    }
    if !LLVMIsAConstantStruct(constant).is_null()
        || !LLVMIsAConstantArray(constant).is_null()
        || !LLVMIsAConstantVector(constant).is_null()
        || !LLVMIsAConstantDataArray(constant).is_null()
        || !LLVMIsAConstantDataVector(constant).is_null()
    {
        let count = LLVMGetNumOperands(constant);
        return (0..count)
            .any(|index| constant_has_pointer_flow(LLVMGetOperand(constant, index as u32)));
    }
    is_pointer_like_type(LLVMTypeOf(constant))
}

unsafe fn constant_pointer_operand_keys(constant: LLVMValueRef) -> Vec<String> {
    let mut out = BTreeSet::new();
    collect_constant_pointer_operand_keys(constant, &mut out);
    out.into_iter().collect()
}

unsafe fn collect_constant_pointer_operand_keys(
    constant: LLVMValueRef,
    out: &mut BTreeSet<String>,
) {
    if !LLVMIsAFunction(constant).is_null()
        || !LLVMIsAGlobalVariable(constant).is_null()
        || !LLVMIsAGlobalAlias(constant).is_null()
        || !LLVMIsAGlobalIFunc(constant).is_null()
    {
        out.insert(format!("@{}", value_name(constant)));
        return;
    }
    let count = LLVMGetNumOperands(constant);
    for index in 0..count {
        collect_constant_pointer_operand_keys(LLVMGetOperand(constant, index as u32), out);
    }
}

unsafe fn call_operand_keys(fctx: &mut FunctionCtx, inst: LLVMValueRef) -> Vec<String> {
    let argc = LLVMGetNumArgOperands(inst);
    let mut out = Vec::with_capacity(argc as usize);
    for index in 0..argc {
        out.push(fctx.operand_key(LLVMGetOperand(inst, index)));
    }
    out
}

unsafe fn call_result_keys(fctx: &mut FunctionCtx, inst: LLVMValueRef) -> Vec<String> {
    if LLVMGetTypeKind(LLVMTypeOf(inst)) == LLVMTypeKind::LLVMVoidTypeKind {
        Vec::new()
    } else {
        vec![fctx.local_key(inst)]
    }
}

unsafe fn direct_callee_name(value: LLVMValueRef) -> Option<String> {
    if !LLVMIsAFunction(value).is_null() {
        return Some(value_name(value));
    }
    if !LLVMIsAConstantExpr(value).is_null() {
        match LLVMGetConstOpcode(value) {
            LLVMOpcode::LLVMBitCast | LLVMOpcode::LLVMAddrSpaceCast => {
                return direct_callee_name(LLVMGetOperand(value, 0));
            }
            _ => {}
        }
    }
    None
}

unsafe fn operand_global_name(value: LLVMValueRef) -> Option<String> {
    if !LLVMIsAGlobalVariable(value).is_null() {
        return Some(value_name(value));
    }
    if !LLVMIsAConstantExpr(value).is_null() {
        match LLVMGetConstOpcode(value) {
            LLVMOpcode::LLVMBitCast
            | LLVMOpcode::LLVMAddrSpaceCast
            | LLVMOpcode::LLVMGetElementPtr => {
                return operand_global_name(LLVMGetOperand(value, 0));
            }
            _ => {}
        }
    }
    None
}

unsafe fn is_pointer_like_type(ty: LLVMTypeRef) -> bool {
    LLVMGetTypeKind(ty) == LLVMTypeKind::LLVMPointerTypeKind
}

unsafe fn loc(value: LLVMValueRef) -> Option<Loc> {
    let line = LLVMGetDebugLocLine(value);
    if line == 0 {
        return None;
    }
    let file = debug_loc_file(value);
    Some(Loc {
        file,
        line,
        col: LLVMGetDebugLocColumn(value),
    })
}

unsafe fn debug_loc_file(value: LLVMValueRef) -> String {
    let mut file_len = 0_u32;
    let file = LLVMGetDebugLocFilename(value, &mut file_len);
    let mut dir_len = 0_u32;
    let dir = LLVMGetDebugLocDirectory(value, &mut dir_len);
    let file = bytes_to_string(file.cast(), file_len as usize);
    let dir = bytes_to_string(dir.cast(), dir_len as usize);
    if !dir.is_empty() && !file.starts_with('/') {
        format!("{}/{}", dir.trim_end_matches('/'), file)
    } else {
        file
    }
}

unsafe fn bump_missing_loc(lowering: &mut LoweringStats, kind: &str, value: LLVMValueRef) {
    if loc(value).is_none() {
        lowering.bump_missing_debug_location(kind);
    }
}

unsafe fn module_identifier(module: LLVMModuleRef) -> String {
    let mut len = 0_usize;
    let ptr = LLVMGetModuleIdentifier(module, &mut len);
    bytes_to_string(ptr.cast(), len)
}

unsafe fn module_source_file(module: LLVMModuleRef) -> String {
    let mut len = 0_usize;
    let ptr = LLVMGetSourceFileName(module, &mut len);
    bytes_to_string(ptr.cast(), len)
}

unsafe fn value_name(value: LLVMValueRef) -> String {
    let mut len = 0_usize;
    let ptr = LLVMGetValueName2(value, &mut len);
    bytes_to_string(ptr.cast(), len)
}

unsafe fn value_string(value: LLVMValueRef) -> String {
    let ptr = LLVMPrintValueToString(value);
    take_message(ptr)
}

unsafe fn type_string(ty: LLVMTypeRef) -> String {
    let ptr = LLVMPrintTypeToString(ty);
    take_message(ptr)
}

unsafe fn take_message(message: *mut c_char) -> String {
    if message.is_null() {
        return "LLVM error".to_string();
    }
    let out = CStr::from_ptr(message).to_string_lossy().into_owned();
    LLVMDisposeMessage(message);
    out
}

unsafe fn bytes_to_string(ptr: *const c_char, len: usize) -> String {
    if ptr.is_null() || len == 0 {
        return String::new();
    }
    let bytes = std::slice::from_raw_parts(ptr.cast::<u8>(), len);
    String::from_utf8_lossy(bytes).into_owned()
}

unsafe fn constant_i64(value: LLVMValueRef) -> Option<i64> {
    if LLVMIsAConstantInt(value).is_null() {
        return None;
    }
    Some(LLVMConstIntGetSExtValue(value))
}

unsafe fn collect_functions(module: LLVMModuleRef) -> Vec<LLVMValueRef> {
    let mut out = Vec::new();
    let mut current = LLVMGetFirstFunction(module);
    while !current.is_null() {
        out.push(current);
        current = LLVMGetNextFunction(current);
    }
    out
}

unsafe fn collect_globals(module: LLVMModuleRef) -> Vec<LLVMValueRef> {
    let mut out = Vec::new();
    let mut current = LLVMGetFirstGlobal(module);
    while !current.is_null() {
        out.push(current);
        current = LLVMGetNextGlobal(current);
    }
    out
}

unsafe fn collect_aliases(module: LLVMModuleRef) -> Vec<LLVMValueRef> {
    let mut out = Vec::new();
    let mut current = LLVMGetFirstGlobalAlias(module);
    while !current.is_null() {
        out.push(current);
        current = LLVMGetNextGlobalAlias(current);
    }
    out
}

unsafe fn collect_ifuncs(module: LLVMModuleRef) -> Vec<LLVMValueRef> {
    let mut out = Vec::new();
    let mut current = LLVMGetFirstGlobalIFunc(module);
    while !current.is_null() {
        out.push(current);
        current = LLVMGetNextGlobalIFunc(current);
    }
    out
}

fn opcode_key(opcode: LLVMOpcode) -> &'static str {
    match opcode {
        LLVMOpcode::LLVMRet => "ret",
        LLVMOpcode::LLVMBr => "br",
        LLVMOpcode::LLVMSwitch => "switch",
        LLVMOpcode::LLVMIndirectBr => "indirectbr",
        LLVMOpcode::LLVMInvoke => "invoke",
        LLVMOpcode::LLVMUnreachable => "unreachable",
        LLVMOpcode::LLVMCallBr => "callbr",
        LLVMOpcode::LLVMAlloca => "alloca",
        LLVMOpcode::LLVMLoad => "load",
        LLVMOpcode::LLVMStore => "store",
        LLVMOpcode::LLVMGetElementPtr => "getelementptr",
        LLVMOpcode::LLVMPtrToInt => "ptrtoint",
        LLVMOpcode::LLVMIntToPtr => "inttoptr",
        LLVMOpcode::LLVMBitCast => "bitcast",
        LLVMOpcode::LLVMAddrSpaceCast => "addrspacecast",
        LLVMOpcode::LLVMCall => "call",
        LLVMOpcode::LLVMExtractElement => "extractelement",
        LLVMOpcode::LLVMInsertElement => "insertelement",
        LLVMOpcode::LLVMShuffleVector => "shufflevector",
        LLVMOpcode::LLVMExtractValue => "extractvalue",
        LLVMOpcode::LLVMInsertValue => "insertvalue",
        LLVMOpcode::LLVMLandingPad => "landingpad",
        LLVMOpcode::LLVMAtomicCmpXchg => "cmpxchg",
        LLVMOpcode::LLVMAtomicRMW => "atomicrmw",
        _ => "other",
    }
}

fn is_exported(linkage: LLVMLinkage, visibility: LLVMVisibility, dll: LLVMDLLStorageClass) -> bool {
    visibility == LLVMVisibility::LLVMDefaultVisibility
        && !matches!(
            linkage,
            LLVMLinkage::LLVMPrivateLinkage
                | LLVMLinkage::LLVMInternalLinkage
                | LLVMLinkage::LLVMAvailableExternallyLinkage
        )
        || dll == LLVMDLLStorageClass::LLVMDLLExportStorageClass
}

fn cc_key(cc: u32, lowering: &mut LoweringStats) -> String {
    let key = if cc == 0 {
        "ccc".to_string()
    } else {
        format!("cc{cc}")
    };
    if key != "ccc" {
        lowering.bump_non_ccc(key.clone());
    }
    key
}

fn is_skipped_intrinsic(name: &str) -> bool {
    name.starts_with("llvm.dbg.")
}

fn global_init_temp(temp_ordinal: &mut u64) -> String {
    let value = format!("@__global_init::{}", *temp_ordinal);
    *temp_ordinal += 1;
    value
}

fn push_unknown(
    body: &mut Vec<Stmt>,
    op: impl Into<String>,
    operands: Vec<String>,
    results: Vec<String>,
    reason: impl Into<String>,
    loc: Option<Loc>,
    lowering: &mut LoweringStats,
) {
    body.push(Stmt::Unknown {
        op: op.into(),
        operands,
        results,
        reason: reason.into(),
        loc,
    });
    lowering.bump_modeled("unknown");
}
