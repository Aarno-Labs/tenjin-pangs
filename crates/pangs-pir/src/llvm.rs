use std::collections::BTreeSet;
use std::path::Path;

use either::Either;
use llvm_ir::constant::Constant;
use llvm_ir::function::{CallingConvention, FunctionDeclaration, ParameterAttribute};
use llvm_ir::instruction::{Call, InlineAssembly, Instruction, Load, Store};
use llvm_ir::module::{DLLStorageClass, Linkage, Visibility};
use llvm_ir::terminator::{Invoke, Terminator};
use llvm_ir::types::{FPType, Type, TypeRef};
use llvm_ir::{DebugLoc, Function, Module, Name, Operand};

use crate::{AbiClass, Access, Func, Global, Loc, Param, Pir, PirError, Signature, Stmt};

pub fn lower_path(path: &Path) -> Result<Pir, PirError> {
    let module = match path.extension().and_then(|ext| ext.to_str()) {
        Some("bc") => Module::from_bc_path(path),
        Some("ll") => Module::from_ir_path(path),
        _ => unreachable!("caller filters extensions"),
    }
    .map_err(|message| PirError::Llvm {
        path: path.display().to_string(),
        message,
    })?;
    Ok(lower_module(&module))
}

fn lower_module(module: &Module) -> Pir {
    let func_names = module
        .functions
        .iter()
        .filter(|f| !is_skipped_intrinsic(&f.name))
        .map(|f| f.name.clone())
        .chain(
            module
                .func_declarations
                .iter()
                .filter(|f| !is_skipped_intrinsic(&f.name))
                .map(|f| f.name.clone()),
        )
        .collect::<BTreeSet<_>>();
    let global_names = module
        .global_vars
        .iter()
        .map(|g| name_key(&g.name))
        .collect::<BTreeSet<_>>();

    let address_taken = collect_address_taken(module, &func_names);

    let mut functions = Vec::new();
    for function in module
        .functions
        .iter()
        .filter(|f| !is_skipped_intrinsic(&f.name))
    {
        functions.push(lower_function(
            function,
            &func_names,
            &global_names,
            &address_taken,
        ));
    }
    for decl in module
        .func_declarations
        .iter()
        .filter(|f| !is_skipped_intrinsic(&f.name))
    {
        functions.push(lower_decl(decl, &address_taken));
    }

    let globals = module
        .global_vars
        .iter()
        .map(|global| Global {
            key: name_key(&global.name),
            file: global.debugloc.as_ref().map(loc_file),
            line: global.debugloc.as_ref().map(|loc| loc.line),
            is_const: global.is_constant,
            mutable: !global.is_constant,
            exported: is_exported(global.linkage, global.visibility, global.dll_storage_class),
        })
        .collect();

    Pir {
        module: module.name.clone(),
        source: Some(module.source_file_name.clone()),
        functions,
        globals,
    }
}

fn lower_function(
    function: &Function,
    func_names: &BTreeSet<String>,
    global_names: &BTreeSet<String>,
    address_taken: &BTreeSet<String>,
) -> Func {
    let mut body = Vec::new();
    for block in &function.basic_blocks {
        for instr in &block.instrs {
            lower_instruction(instr, func_names, global_names, &mut body);
        }
        lower_terminator(&block.term, func_names, &mut body);
    }

    Func {
        key: function.name.clone(),
        sig: signature(
            &function.return_type,
            function.parameters.iter().map(|p| (&p.ty, &p.attributes)),
            function.is_var_arg,
            function.calling_convention,
        ),
        file: function.debugloc.as_ref().map(loc_file),
        line: function.debugloc.as_ref().map(|loc| loc.line),
        external: false,
        exported: is_exported(
            function.linkage,
            function.visibility,
            function.dll_storage_class,
        ),
        address_taken: address_taken.contains(&function.name),
        body,
    }
}

fn lower_decl(decl: &FunctionDeclaration, address_taken: &BTreeSet<String>) -> Func {
    Func {
        key: decl.name.clone(),
        sig: signature(
            &decl.return_type,
            decl.parameters.iter().map(|p| (&p.ty, &p.attributes)),
            decl.is_var_arg,
            decl.calling_convention,
        ),
        file: decl.debugloc.as_ref().map(loc_file),
        line: decl.debugloc.as_ref().map(|loc| loc.line),
        external: true,
        exported: is_exported(decl.linkage, decl.visibility, decl.dll_storage_class),
        address_taken: address_taken.contains(&decl.name),
        body: Vec::new(),
    }
}

fn collect_address_taken(module: &Module, func_names: &BTreeSet<String>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for global in &module.global_vars {
        if let Some(init) = &global.initializer {
            collect_constant_func_refs(init, func_names, &mut out);
        }
    }
    for function in &module.functions {
        for block in &function.basic_blocks {
            for instr in &block.instrs {
                collect_instr_address_taken(instr, func_names, &mut out);
            }
            collect_term_address_taken(&block.term, func_names, &mut out);
        }
    }
    out
}

fn collect_instr_address_taken(
    instr: &Instruction,
    func_names: &BTreeSet<String>,
    out: &mut BTreeSet<String>,
) {
    match instr {
        Instruction::Call(call) => {
            if called_function_name(&call.function).is_none() {
                collect_either_operand_func_refs(&call.function, func_names, out);
            }
            for (arg, _) in &call.arguments {
                collect_operand_func_refs(arg, func_names, out);
            }
        }
        Instruction::Store(store) => {
            collect_operand_func_refs(&store.value, func_names, out);
            collect_operand_func_refs(&store.address, func_names, out);
        }
        _ => {}
    }
}

fn collect_term_address_taken(
    term: &Terminator,
    func_names: &BTreeSet<String>,
    out: &mut BTreeSet<String>,
) {
    if let Terminator::Invoke(invoke) = term {
        if called_function_name(&invoke.function).is_none() {
            collect_either_operand_func_refs(&invoke.function, func_names, out);
        }
        for (arg, _) in &invoke.arguments {
            collect_operand_func_refs(arg, func_names, out);
        }
    }
}

fn collect_either_operand_func_refs(
    function: &Either<InlineAssembly, Operand>,
    func_names: &BTreeSet<String>,
    out: &mut BTreeSet<String>,
) {
    if let Either::Right(operand) = function {
        collect_operand_func_refs(operand, func_names, out);
    }
}

fn collect_operand_func_refs(
    operand: &Operand,
    func_names: &BTreeSet<String>,
    out: &mut BTreeSet<String>,
) {
    if let Operand::ConstantOperand(constant) = operand {
        collect_constant_func_refs(constant, func_names, out);
    }
}

fn collect_constant_func_refs(
    constant: &Constant,
    func_names: &BTreeSet<String>,
    out: &mut BTreeSet<String>,
) {
    match constant {
        Constant::GlobalReference { name, .. } => {
            let key = name_key(name);
            if func_names.contains(&key) {
                out.insert(key);
            }
        }
        Constant::Struct { values, .. }
        | Constant::Array {
            elements: values, ..
        } => {
            for value in values {
                collect_constant_func_refs(value, func_names, out);
            }
        }
        Constant::Vector(values) => {
            for value in values {
                collect_constant_func_refs(value, func_names, out);
            }
        }
        Constant::BitCast(expr) => collect_constant_func_refs(&expr.operand, func_names, out),
        Constant::GetElementPtr(expr) => collect_constant_func_refs(&expr.address, func_names, out),
        _ => {}
    }
}

fn lower_instruction(
    instr: &Instruction,
    func_names: &BTreeSet<String>,
    global_names: &BTreeSet<String>,
    body: &mut Vec<Stmt>,
) {
    match instr {
        Instruction::Call(call) => lower_call(call, func_names, body),
        Instruction::Load(load) => lower_load(load, global_names, body),
        Instruction::Store(store) => lower_store(store, global_names, body),
        _ => {}
    }
}

fn lower_terminator(term: &Terminator, func_names: &BTreeSet<String>, body: &mut Vec<Stmt>) {
    if let Terminator::Invoke(invoke) = term {
        lower_invoke(invoke, func_names, body);
    }
}

fn lower_call(call: &Call, func_names: &BTreeSet<String>, body: &mut Vec<Stmt>) {
    let Some(sig) = call_signature_from_operand(
        &call.function,
        call.arguments.iter().map(|a| &a.1),
        call.calling_convention,
    ) else {
        return;
    };
    match called_function_name(&call.function) {
        Some(callee) if is_skipped_intrinsic(&callee) => {}
        Some(callee) if func_names.contains(&callee) => body.push(Stmt::CallDirect {
            callee,
            sig,
            loc: loc(call.debugloc.as_ref()),
        }),
        _ => body.push(Stmt::CallIndirect {
            operand: operand_key_either(&call.function),
            sig,
            loc: loc(call.debugloc.as_ref()),
        }),
    }
}

fn lower_invoke(invoke: &Invoke, func_names: &BTreeSet<String>, body: &mut Vec<Stmt>) {
    let Some(sig) = call_signature_from_operand(
        &invoke.function,
        invoke.arguments.iter().map(|a| &a.1),
        invoke.calling_convention,
    ) else {
        return;
    };
    match called_function_name(&invoke.function) {
        Some(callee) if is_skipped_intrinsic(&callee) => {}
        Some(callee) if func_names.contains(&callee) => body.push(Stmt::CallDirect {
            callee,
            sig,
            loc: loc(invoke.debugloc.as_ref()),
        }),
        _ => body.push(Stmt::CallIndirect {
            operand: operand_key_either(&invoke.function),
            sig,
            loc: loc(invoke.debugloc.as_ref()),
        }),
    }
}

fn lower_load(load: &Load, global_names: &BTreeSet<String>, body: &mut Vec<Stmt>) {
    if let Some(global) =
        operand_global_name(&load.address).filter(|name| global_names.contains(name))
    {
        body.push(Stmt::GlobalRef {
            global,
            access: Access::Ref,
            loc: loc(load.debugloc.as_ref()),
        });
    }
}

fn lower_store(store: &Store, global_names: &BTreeSet<String>, body: &mut Vec<Stmt>) {
    if let Some(global) =
        operand_global_name(&store.address).filter(|name| global_names.contains(name))
    {
        body.push(Stmt::GlobalRef {
            global,
            access: Access::Mod,
            loc: loc(store.debugloc.as_ref()),
        });
    }
}

fn call_signature_from_operand<'a>(
    function: &Either<InlineAssembly, Operand>,
    arg_attrs: impl Iterator<Item = &'a Vec<ParameterAttribute>>,
    cc: CallingConvention,
) -> Option<Signature> {
    let Either::Right(operand) = function else {
        return None;
    };
    let pointee_type = callee_function_type(operand)?;
    let Type::FuncType {
        result_type,
        param_types,
        is_var_arg,
    } = pointee_type.as_ref()
    else {
        return None;
    };
    Some(signature(
        result_type,
        param_types.iter().zip(arg_attrs),
        *is_var_arg,
        cc,
    ))
}

fn signature<'a, 'b>(
    ret: &TypeRef,
    params: impl Iterator<Item = (&'a TypeRef, &'b Vec<ParameterAttribute>)>,
    vararg: bool,
    cc: CallingConvention,
) -> Signature {
    Signature {
        ret: abi_class(ret),
        params: params
            .map(|(ty, attrs)| param_class(ty, attrs))
            .collect::<Vec<_>>(),
        vararg,
        cc: cc_key(cc),
    }
}

fn param_class(ty: &TypeRef, attrs: &[ParameterAttribute]) -> Param {
    for attr in attrs {
        match attr {
            ParameterAttribute::ByVal(ty) => {
                return Param::Byval {
                    size: type_size_key(ty),
                }
            }
            ParameterAttribute::SRet(ty) => {
                return Param::Sret {
                    size: type_size_key(ty),
                }
            }
            _ => {}
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

fn abi_class(ty: &TypeRef) -> AbiClass {
    match ty.as_ref() {
        Type::VoidType => AbiClass::Void,
        Type::IntegerType { bits } if *bits <= 128 => AbiClass::Integer,
        Type::PointerType { .. } => AbiClass::Integer,
        Type::FPType(FPType::Single) | Type::FPType(FPType::Double) => AbiClass::Sse,
        Type::FPType(FPType::X86_FP80) => AbiClass::X87,
        Type::FPType(FPType::FP128) | Type::FPType(FPType::PPC_FP128) => AbiClass::Fp128,
        _ => AbiClass::Integer,
    }
}

fn type_size_key(ty: &TypeRef) -> u64 {
    match ty.as_ref() {
        Type::IntegerType { bits } => u64::from(*bits).div_ceil(8),
        Type::PointerType { .. } => 8,
        Type::FPType(FPType::Single) => 4,
        Type::FPType(FPType::Double) => 8,
        Type::FPType(FPType::X86_FP80) => 16,
        Type::FPType(FPType::FP128) | Type::FPType(FPType::PPC_FP128) => 16,
        Type::ArrayType {
            element_type,
            num_elements,
        } => type_size_key(element_type).saturating_mul(*num_elements as u64),
        Type::StructType { element_types, .. } => element_types.iter().map(type_size_key).sum(),
        _ => 0,
    }
}

fn called_function_name(function: &Either<InlineAssembly, Operand>) -> Option<String> {
    match function {
        Either::Right(operand) => operand_global_name(operand),
        Either::Left(_) => None,
    }
}

fn operand_global_name(operand: &Operand) -> Option<String> {
    match operand {
        Operand::ConstantOperand(cref) => constant_global_name(cref),
        _ => None,
    }
}

fn constant_global_name(constant: &Constant) -> Option<String> {
    match constant {
        Constant::GlobalReference { name, .. } => Some(name_key(name)),
        Constant::BitCast(expr) => constant_global_name(&expr.operand),
        Constant::GetElementPtr(expr) => constant_global_name(&expr.address),
        _ => None,
    }
}

fn callee_function_type(operand: &Operand) -> Option<TypeRef> {
    match operand {
        Operand::LocalOperand { ty, .. } => match ty.as_ref() {
            Type::PointerType { pointee_type, .. } => Some(pointee_type.clone()),
            Type::FuncType { .. } => Some(ty.clone()),
            _ => None,
        },
        Operand::ConstantOperand(cref) => match cref.as_ref() {
            Constant::GlobalReference { ty, .. } => Some(ty.clone()),
            Constant::BitCast(expr) => match expr.to_type.as_ref() {
                Type::PointerType { pointee_type, .. } => Some(pointee_type.clone()),
                Type::FuncType { .. } => Some(expr.to_type.clone()),
                _ => None,
            },
            _ => None,
        },
        Operand::MetadataOperand => None,
    }
}

fn operand_key_either(function: &Either<InlineAssembly, Operand>) -> String {
    match function {
        Either::Left(_) => "inline_asm".to_string(),
        Either::Right(operand) => format!("{operand}"),
    }
}

fn is_exported(linkage: Linkage, visibility: Visibility, dll: DLLStorageClass) -> bool {
    visibility == Visibility::Default
        && !matches!(
            linkage,
            Linkage::Private | Linkage::Internal | Linkage::AvailableExternally
        )
        || dll == DLLStorageClass::Export
}

fn cc_key(cc: CallingConvention) -> String {
    match cc {
        CallingConvention::C => "ccc".to_string(),
        other => format!("{other:?}"),
    }
}

fn is_skipped_intrinsic(name: &str) -> bool {
    name.starts_with("llvm.dbg.")
}

fn loc(debugloc: Option<&DebugLoc>) -> Option<Loc> {
    debugloc.map(|loc| Loc {
        file: loc_file(loc),
        line: loc.line,
        col: loc.col.unwrap_or(0),
    })
}

fn loc_file(loc: &DebugLoc) -> String {
    match &loc.directory {
        Some(dir) if !dir.is_empty() && !loc.filename.starts_with('/') => {
            format!("{}/{}", dir.trim_end_matches('/'), loc.filename)
        }
        _ => loc.filename.clone(),
    }
}

fn name_key(name: &Name) -> String {
    match name {
        Name::Name(name) => (**name).clone(),
        Name::Number(num) => num.to_string(),
    }
}
