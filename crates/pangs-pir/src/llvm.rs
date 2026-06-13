use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use either::Either;
use llvm_ir::constant::{Constant, ConstantRef};
use llvm_ir::function::{CallingConvention, FunctionDeclaration, ParameterAttribute};
use llvm_ir::instruction::{
    AddrSpaceCast, Alloca, AtomicRMW, BitCast, Call, CmpXchg, ExtractElement, ExtractValue, Freeze,
    GetElementPtr, InlineAssembly, InsertElement, InsertValue, Instruction, IntToPtr, LandingPad,
    Load, Phi, PtrToInt, Select, ShuffleVector, Store,
};
use llvm_ir::module::{DLLStorageClass, GlobalAlias, Linkage, Visibility};
use llvm_ir::terminator::{Invoke, Terminator};
use llvm_ir::types::{FPType, NamedStructDef, Type, TypeRef, Typed};
use llvm_ir::{DebugLoc, Function, Module, Name, Operand};

use crate::{
    AbiClass, Access, Func, Global, Loc, LoweringStats, Param, Pir, PirError, Signature, Stmt,
};

type AliasMap = BTreeMap<String, AliasTarget>;

#[derive(Debug, Clone, PartialEq, Eq)]
enum AliasTarget {
    Function(String),
    Global(String),
}

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
    let mut lowering = LoweringStats {
        functions: module
            .functions
            .iter()
            .filter(|f| !is_skipped_intrinsic(&f.name))
            .count() as u64,
        declarations: module
            .func_declarations
            .iter()
            .filter(|f| !is_skipped_intrinsic(&f.name))
            .count() as u64,
        globals: module.global_vars.len() as u64,
        aliases: module.global_aliases.len() as u64,
        ifuncs: module.global_ifuncs.len() as u64,
        ..LoweringStats::default()
    };
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
    let ifunc_names = module
        .global_ifuncs
        .iter()
        .map(|ifunc| name_key(&ifunc.name))
        .collect::<BTreeSet<_>>();
    let aliases = collect_aliases(
        &module.global_aliases,
        &func_names,
        &global_names,
        &mut lowering,
    );
    for ifunc in &module.global_ifuncs {
        lowering.bump_tainted(format!("ifunc:{}", name_key(&ifunc.name)));
    }

    let address_taken = collect_address_taken(module, &func_names, &aliases);

    let mut functions = Vec::new();
    for function in module
        .functions
        .iter()
        .filter(|f| !is_skipped_intrinsic(&f.name))
    {
        functions.push(lower_function(
            module,
            function,
            &func_names,
            &global_names,
            &aliases,
            &ifunc_names,
            &address_taken,
            &mut lowering,
        ));
    }
    for decl in module
        .func_declarations
        .iter()
        .filter(|f| !is_skipped_intrinsic(&f.name))
    {
        functions.push(lower_decl(module, decl, &address_taken, &mut lowering));
    }

    let globals = module
        .global_vars
        .iter()
        .map(|global| {
            if global.debugloc.is_none() {
                lowering.bump_missing_debug_location("global");
            }
            Global {
                key: name_key(&global.name),
                file: global.debugloc.as_ref().map(loc_file),
                line: global.debugloc.as_ref().map(|loc| loc.line),
                is_const: global.is_constant,
                mutable: !global.is_constant,
                exported: is_exported(global.linkage, global.visibility, global.dll_storage_class),
            }
        })
        .collect();
    let global_init = lower_global_initializers(module, &global_names, &aliases, &mut lowering);

    Pir {
        module: module.name.clone(),
        source: Some(module.source_file_name.clone()),
        lowering,
        functions,
        globals,
        global_init,
    }
}

fn collect_aliases(
    global_aliases: &[GlobalAlias],
    func_names: &BTreeSet<String>,
    global_names: &BTreeSet<String>,
    lowering: &mut LoweringStats,
) -> AliasMap {
    let mut aliases = AliasMap::new();
    for alias in global_aliases {
        let alias_key = name_key(&alias.name);
        if !is_non_interposable_alias(alias) {
            lowering.bump_tainted(format!("alias_interposable:{alias_key}"));
            continue;
        }

        let Some(target) = constant_global_name(&alias.aliasee) else {
            lowering.bump_tainted(format!("alias_unresolved:{alias_key}"));
            continue;
        };
        if func_names.contains(&target) {
            aliases.insert(alias_key, AliasTarget::Function(target));
            lowering.bump_modeled("alias_function_resolved");
        } else if global_names.contains(&target) {
            aliases.insert(alias_key, AliasTarget::Global(target));
            lowering.bump_modeled("alias_global_resolved");
        } else {
            lowering.bump_tainted(format!("alias_unresolved:{alias_key}"));
        }
    }
    aliases
}

fn is_non_interposable_alias(alias: &GlobalAlias) -> bool {
    matches!(alias.linkage, Linkage::Private | Linkage::Internal)
}

fn lower_global_initializers(
    module: &Module,
    global_names: &BTreeSet<String>,
    aliases: &AliasMap,
    lowering: &mut LoweringStats,
) -> Vec<Stmt> {
    let mut body = Vec::new();
    let mut temp_ordinal = 0_u64;

    for global in &module.global_vars {
        let Some(initializer) = &global.initializer else {
            continue;
        };
        let global_key = name_key(&global.name);
        let address = format!("@{global_key}");
        body.push(Stmt::GlobalRef {
            global: global_key,
            access: Access::Mod,
            loc: loc(global.debugloc.as_ref()),
        });
        lowering.bump_modeled("global_init_mod");

        if !lower_global_initializer_value(
            module,
            &address,
            initializer,
            global_names,
            aliases,
            &mut body,
            &mut temp_ordinal,
            lowering,
        ) {
            lowering.bump_skipped("global_initializer_non_pointer");
        }
    }

    body
}

fn lower_global_initializer_value(
    module: &Module,
    address: &str,
    constant: &Constant,
    global_names: &BTreeSet<String>,
    aliases: &AliasMap,
    body: &mut Vec<Stmt>,
    temp_ordinal: &mut u64,
    lowering: &mut LoweringStats,
) -> bool {
    match constant {
        Constant::Struct {
            values, is_packed, ..
        } => {
            let mut found = false;
            let element_types = values
                .iter()
                .map(|value| value.get_type(&module.types))
                .collect::<Vec<_>>();
            for (index, value) in values.iter().enumerate() {
                let field_address = struct_field_address(
                    module,
                    address,
                    &element_types,
                    *is_packed,
                    index,
                    body,
                    temp_ordinal,
                    lowering,
                );
                found |= lower_global_initializer_value(
                    module,
                    &field_address,
                    value,
                    global_names,
                    aliases,
                    body,
                    temp_ordinal,
                    lowering,
                );
            }
            found
        }
        Constant::Array {
            element_type,
            elements: values,
        } => {
            let mut found = false;
            for (index, value) in values.iter().enumerate() {
                let field_address = sequential_element_address(
                    module,
                    address,
                    element_type,
                    index,
                    body,
                    temp_ordinal,
                    lowering,
                );
                found |= lower_global_initializer_value(
                    module,
                    &field_address,
                    value,
                    global_names,
                    aliases,
                    body,
                    temp_ordinal,
                    lowering,
                );
            }
            found
        }
        Constant::Vector(values) => {
            let mut found = false;
            let element_type = values.first().map(|value| value.get_type(&module.types));
            for (index, value) in values.iter().enumerate() {
                let field_address = element_type
                    .as_ref()
                    .map(|element_type| {
                        sequential_element_address(
                            module,
                            address,
                            element_type,
                            index,
                            body,
                            temp_ordinal,
                            lowering,
                        )
                    })
                    .unwrap_or_else(|| address.to_string());
                found |= lower_global_initializer_value(
                    module,
                    &field_address,
                    value,
                    global_names,
                    aliases,
                    body,
                    temp_ordinal,
                    lowering,
                );
            }
            found
        }
        _ if constant_has_pointer_flow(module, constant) => {
            let value =
                lower_constant_expr_value(module, constant, aliases, body, temp_ordinal, lowering);
            body.push(Stmt::Store {
                address: address.to_string(),
                value: value.clone(),
                loc: None,
            });
            lowering.bump_modeled("global_init_store");
            if let Some(global) = constant_global_name(constant)
                .and_then(|name| resolve_global_alias(&name, aliases).or(Some(name)))
                .filter(|name| global_names.contains(name))
            {
                body.push(Stmt::GlobalRef {
                    global,
                    access: Access::Ref,
                    loc: None,
                });
                lowering.bump_modeled("global_init_ref");
            }
            true
        }
        _ => false,
    }
}

fn struct_field_address(
    module: &Module,
    base: &str,
    element_types: &[TypeRef],
    is_packed: bool,
    index: usize,
    body: &mut Vec<Stmt>,
    temp_ordinal: &mut u64,
    lowering: &mut LoweringStats,
) -> String {
    let byte_off = struct_field_offset(module, element_types, is_packed, index)
        .and_then(|byte_off| i64::try_from(byte_off).ok());
    global_init_element_address(base, byte_off, body, temp_ordinal, lowering)
}

fn sequential_element_address(
    module: &Module,
    base: &str,
    element_type: &TypeRef,
    index: usize,
    body: &mut Vec<Stmt>,
    temp_ordinal: &mut u64,
    lowering: &mut LoweringStats,
) -> String {
    let byte_off = type_alloc_size(module, element_type)
        .and_then(|stride| i128::from(stride).checked_mul(i128::try_from(index).ok()?))
        .and_then(|byte_off| i64::try_from(byte_off).ok());
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

fn lower_constant_expr_value(
    module: &Module,
    constant: &Constant,
    aliases: &AliasMap,
    body: &mut Vec<Stmt>,
    temp_ordinal: &mut u64,
    lowering: &mut LoweringStats,
) -> String {
    match constant {
        Constant::GlobalReference { name, .. } => {
            let name = name_key(name);
            format!("@{}", resolve_symbol_alias(&name, aliases).unwrap_or(name))
        }
        Constant::BitCast(expr) => {
            let source = lower_constant_expr_value(
                module,
                &expr.operand,
                aliases,
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
        Constant::AddrSpaceCast(expr) => {
            let source = lower_constant_expr_value(
                module,
                &expr.operand,
                aliases,
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
        Constant::GetElementPtr(expr) => {
            let base = lower_constant_expr_value(
                module,
                &expr.address,
                aliases,
                body,
                temp_ordinal,
                lowering,
            );
            let dest = global_init_temp(temp_ordinal);
            body.push(Stmt::Gep {
                dest: dest.clone(),
                base,
                byte_off: constant_gep_byte_offset(module, expr, lowering),
                loc: None,
            });
            lowering.bump_modeled("global_init_gep");
            dest
        }
        Constant::PtrToInt(expr) => {
            let source = lower_constant_expr_value(
                module,
                &expr.operand,
                aliases,
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
        Constant::IntToPtr(expr) => {
            let source = constant_value_key(&expr.operand);
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
        Constant::Select(expr) => {
            let true_value = lower_constant_expr_value(
                module,
                &expr.true_value,
                aliases,
                body,
                temp_ordinal,
                lowering,
            );
            let false_value = lower_constant_expr_value(
                module,
                &expr.false_value,
                aliases,
                body,
                temp_ordinal,
                lowering,
            );
            let dest = global_init_temp(temp_ordinal);
            body.push(Stmt::Assign {
                dest: dest.clone(),
                sources: vec![true_value, false_value],
                loc: None,
            });
            lowering.bump_modeled("global_init_select");
            dest
        }
        _ => {
            let dest = global_init_temp(temp_ordinal);
            lowering.bump_tainted(format!(
                "global_initializer_unmodeled_pointer_constant:{}",
                constant_opcode(constant)
            ));
            push_unknown(
                body,
                format!("constant_expr:{}", constant_opcode(constant)),
                constant_pointer_operand_keys(module, constant, aliases),
                vec![dest.clone()],
                "global_initializer_pointer_constant",
                None,
                lowering,
            );
            dest
        }
    }
}

fn lower_function(
    module: &Module,
    function: &Function,
    func_names: &BTreeSet<String>,
    global_names: &BTreeSet<String>,
    aliases: &AliasMap,
    ifunc_names: &BTreeSet<String>,
    address_taken: &BTreeSet<String>,
    lowering: &mut LoweringStats,
) -> Func {
    let mut body = Vec::new();
    if function.debugloc.is_none() {
        lowering.bump_missing_debug_location("function");
    }
    lower_personality_function(module, function, aliases, lowering);
    for block in &function.basic_blocks {
        for instr in &block.instrs {
            lowering.bump_instruction(instruction_opcode(instr));
            lower_instruction(
                module,
                &function.name,
                instr,
                func_names,
                global_names,
                aliases,
                ifunc_names,
                &mut body,
                lowering,
            );
        }
        lowering.bump_terminator(terminator_opcode(&block.term));
        lower_terminator(
            module,
            &function.name,
            &block.term,
            func_names,
            aliases,
            ifunc_names,
            &mut body,
            lowering,
        );
    }

    let sig = signature(
        module,
        &function.return_type,
        function.parameters.iter().map(|p| (&p.ty, &p.attributes)),
        function.is_var_arg,
        function.calling_convention,
        lowering,
    );
    Func {
        key: function.name.clone(),
        sig,
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

fn lower_decl(
    module: &Module,
    decl: &FunctionDeclaration,
    address_taken: &BTreeSet<String>,
    lowering: &mut LoweringStats,
) -> Func {
    if decl.debugloc.is_none() {
        lowering.bump_missing_debug_location("declaration");
    }
    let sig = signature(
        module,
        &decl.return_type,
        decl.parameters.iter().map(|p| (&p.ty, &p.attributes)),
        decl.is_var_arg,
        decl.calling_convention,
        lowering,
    );
    Func {
        key: decl.name.clone(),
        sig,
        file: decl.debugloc.as_ref().map(loc_file),
        line: decl.debugloc.as_ref().map(|loc| loc.line),
        external: true,
        exported: is_exported(decl.linkage, decl.visibility, decl.dll_storage_class),
        address_taken: address_taken.contains(&decl.name),
        body: Vec::new(),
    }
}

fn collect_address_taken(
    module: &Module,
    func_names: &BTreeSet<String>,
    aliases: &AliasMap,
) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for global in &module.global_vars {
        if let Some(init) = &global.initializer {
            collect_constant_func_refs(init, func_names, aliases, &mut out);
        }
    }
    for function in &module.functions {
        if let Some(personality) = &function.personality_function {
            collect_constant_func_refs(personality, func_names, aliases, &mut out);
        }
        for block in &function.basic_blocks {
            for instr in &block.instrs {
                collect_instr_address_taken(instr, func_names, aliases, &mut out);
            }
            collect_term_address_taken(&block.term, func_names, aliases, &mut out);
        }
    }
    out
}

fn collect_instr_address_taken(
    instr: &Instruction,
    func_names: &BTreeSet<String>,
    aliases: &AliasMap,
    out: &mut BTreeSet<String>,
) {
    match instr {
        Instruction::Call(call) => {
            if called_function_name(&call.function).is_none() {
                collect_either_operand_func_refs(&call.function, func_names, aliases, out);
            }
            for (arg, _) in &call.arguments {
                collect_operand_func_refs(arg, func_names, aliases, out);
            }
        }
        Instruction::Store(store) => {
            collect_operand_func_refs(&store.value, func_names, aliases, out);
            collect_operand_func_refs(&store.address, func_names, aliases, out);
        }
        _ => {}
    }
}

fn collect_term_address_taken(
    term: &Terminator,
    func_names: &BTreeSet<String>,
    aliases: &AliasMap,
    out: &mut BTreeSet<String>,
) {
    if let Terminator::Invoke(invoke) = term {
        if called_function_name(&invoke.function).is_none() {
            collect_either_operand_func_refs(&invoke.function, func_names, aliases, out);
        }
        for (arg, _) in &invoke.arguments {
            collect_operand_func_refs(arg, func_names, aliases, out);
        }
    }
}

fn collect_either_operand_func_refs(
    function: &Either<InlineAssembly, Operand>,
    func_names: &BTreeSet<String>,
    aliases: &AliasMap,
    out: &mut BTreeSet<String>,
) {
    if let Either::Right(operand) = function {
        collect_operand_func_refs(operand, func_names, aliases, out);
    }
}

fn collect_operand_func_refs(
    operand: &Operand,
    func_names: &BTreeSet<String>,
    aliases: &AliasMap,
    out: &mut BTreeSet<String>,
) {
    if let Operand::ConstantOperand(constant) = operand {
        collect_constant_func_refs(constant, func_names, aliases, out);
    }
}

fn collect_constant_func_refs(
    constant: &Constant,
    func_names: &BTreeSet<String>,
    aliases: &AliasMap,
    out: &mut BTreeSet<String>,
) {
    match constant {
        Constant::GlobalReference { name, .. } => {
            let key = name_key(name);
            if let Some(target) = resolve_function_alias(&key, aliases) {
                out.insert(target);
            } else if func_names.contains(&key) {
                out.insert(key);
            }
        }
        Constant::Struct { values, .. }
        | Constant::Array {
            elements: values, ..
        } => {
            for value in values {
                collect_constant_func_refs(value, func_names, aliases, out);
            }
        }
        Constant::Vector(values) => {
            for value in values {
                collect_constant_func_refs(value, func_names, aliases, out);
            }
        }
        Constant::BitCast(expr) => {
            collect_constant_func_refs(&expr.operand, func_names, aliases, out)
        }
        Constant::GetElementPtr(expr) => {
            collect_constant_func_refs(&expr.address, func_names, aliases, out)
        }
        _ => {}
    }
}

fn lower_instruction(
    module: &Module,
    func_name: &str,
    instr: &Instruction,
    func_names: &BTreeSet<String>,
    global_names: &BTreeSet<String>,
    aliases: &AliasMap,
    ifunc_names: &BTreeSet<String>,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    match instr {
        Instruction::Alloca(alloca) => lower_alloca(func_name, alloca, body, lowering),
        Instruction::Load(load) => {
            lower_load(func_name, load, global_names, aliases, body, lowering)
        }
        Instruction::Store(store) => {
            lower_store(func_name, store, global_names, aliases, body, lowering)
        }
        Instruction::CmpXchg(cmpxchg) => lower_cmpxchg(func_name, cmpxchg, body, lowering),
        Instruction::AtomicRMW(atomicrmw) => lower_atomicrmw(func_name, atomicrmw, body, lowering),
        Instruction::GetElementPtr(gep) => lower_gep(module, func_name, gep, body, lowering),
        Instruction::PtrToInt(cast) => lower_ptr_to_int(func_name, cast, body, lowering),
        Instruction::IntToPtr(cast) => lower_int_to_ptr(func_name, cast, body, lowering),
        Instruction::BitCast(cast) => lower_bitcast(module, func_name, cast, body, lowering),
        Instruction::AddrSpaceCast(cast) => {
            lower_addrspacecast(module, func_name, cast, body, lowering)
        }
        Instruction::Phi(phi) => lower_phi(module, func_name, phi, body, lowering),
        Instruction::Select(select) => lower_select(module, func_name, select, body, lowering),
        Instruction::Freeze(freeze) => lower_freeze(func_name, freeze, body, lowering),
        Instruction::ExtractElement(extract) => {
            lower_extract_element(module, func_name, extract, body, lowering)
        }
        Instruction::InsertElement(insert) => {
            lower_insert_element(module, func_name, insert, body, lowering)
        }
        Instruction::ShuffleVector(shuffle) => {
            lower_shuffle_vector(module, func_name, shuffle, body, lowering)
        }
        Instruction::ExtractValue(extract) => {
            lower_extract_value(module, func_name, extract, body, lowering)
        }
        Instruction::InsertValue(insert) => {
            lower_insert_value(module, func_name, insert, body, lowering)
        }
        Instruction::LandingPad(landingpad) => {
            lower_landingpad(module, func_name, landingpad, body, lowering)
        }
        Instruction::Call(call) => lower_call(
            module,
            func_name,
            call,
            func_names,
            aliases,
            ifunc_names,
            body,
            lowering,
        ),
        Instruction::VAArg(va_arg) => {
            lowering.bump_tainted("va_arg");
            push_unknown(
                body,
                "va_arg",
                vec![operand_value_key(func_name, &va_arg.arg_list)],
                vec![local_value_key(func_name, &va_arg.dest)],
                "va_arg",
                loc(va_arg.debugloc.as_ref()),
                lowering,
            );
        }
        _ => lowering.bump_skipped(format!(
            "unmodeled_instruction:{}",
            instruction_opcode(instr)
        )),
    }
}

fn lower_terminator(
    module: &Module,
    func_name: &str,
    term: &Terminator,
    func_names: &BTreeSet<String>,
    aliases: &AliasMap,
    ifunc_names: &BTreeSet<String>,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    match term {
        Terminator::Invoke(invoke) => lower_invoke(
            module,
            func_name,
            invoke,
            func_names,
            aliases,
            ifunc_names,
            body,
            lowering,
        ),
        Terminator::Ret(ret) => {
            body.push(Stmt::Return {
                value: ret
                    .return_operand
                    .as_ref()
                    .map(|op| operand_value_key(func_name, op)),
                loc: loc(ret.debugloc.as_ref()),
            });
            lowering.bump_modeled("return");
            bump_missing_loc(lowering, "return", ret.debugloc.as_ref());
        }
        Terminator::CallBr(callbr) => {
            lowering.bump_tainted("callbr");
            if let Either::Left(_) = &callbr.function {
                push_unknown(
                    body,
                    "callbr",
                    callbr
                        .arguments
                        .iter()
                        .map(|(arg, _)| operand_value_key(func_name, arg))
                        .collect(),
                    vec![local_value_key(func_name, &callbr.result)],
                    "inline_asm_callbr",
                    loc(callbr.debugloc.as_ref()),
                    lowering,
                );
            }
        }
        _ => {}
    }
}

fn lower_alloca(
    func_name: &str,
    alloca: &Alloca,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    body.push(Stmt::Alloca {
        dest: local_value_key(func_name, &alloca.dest),
        ty: alloca.allocated_type.to_string(),
        loc: loc(alloca.debugloc.as_ref()),
    });
    lowering.bump_modeled("alloca");
    bump_missing_loc(lowering, "alloca", alloca.debugloc.as_ref());
}

fn lower_call(
    module: &Module,
    func_name: &str,
    call: &Call,
    func_names: &BTreeSet<String>,
    aliases: &AliasMap,
    ifunc_names: &BTreeSet<String>,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    if let Either::Left(_) = &call.function {
        lowering.bump_tainted("inline_asm");
        push_unknown(
            body,
            "call",
            call.arguments
                .iter()
                .map(|(arg, _)| operand_value_key(func_name, arg))
                .collect(),
            call.dest
                .as_ref()
                .map(|dest| vec![local_value_key(func_name, dest)])
                .unwrap_or_default(),
            "inline_asm",
            loc(call.debugloc.as_ref()),
            lowering,
        );
        return;
    }

    if let Some(callee) = called_function_name(&call.function) {
        if lower_intrinsic_call(module, func_name, &callee, call, body, lowering) {
            return;
        }
        if ifunc_names.contains(&callee) {
            lower_ifunc_call(
                func_name,
                "call",
                &callee,
                &call.arguments,
                call.dest.as_ref(),
                loc(call.debugloc.as_ref()),
                body,
                lowering,
            );
            return;
        }
    }

    let Some(sig) = call_signature_from_operand(
        module,
        &call.function,
        call.arguments.iter().map(|a| &a.1),
        call.calling_convention,
        lowering,
    ) else {
        lowering.bump_skipped("call_without_function_signature");
        return;
    };
    match called_function_name(&call.function) {
        Some(callee) if is_skipped_intrinsic(&callee) => {}
        Some(callee) if resolve_function_name(&callee, func_names, aliases).is_some() => {
            let resolved = resolve_function_name(&callee, func_names, aliases).unwrap();
            if resolved != callee {
                lowering.bump_modeled("alias_call_direct");
            }
            body.push(Stmt::CallDirect {
                callee: resolved,
                sig,
                loc: loc(call.debugloc.as_ref()),
            });
            lowering.bump_modeled("call_direct");
        }
        _ => {
            body.push(Stmt::CallIndirect {
                operand: operand_key_either(func_name, &call.function),
                sig,
                loc: loc(call.debugloc.as_ref()),
            });
            lowering.bump_modeled("call_indirect");
        }
    }
    bump_missing_loc(lowering, "call", call.debugloc.as_ref());
}

fn lower_invoke(
    module: &Module,
    func_name: &str,
    invoke: &Invoke,
    func_names: &BTreeSet<String>,
    aliases: &AliasMap,
    ifunc_names: &BTreeSet<String>,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    lowering.bump_tainted("invoke_exception_control_flow");
    if let Either::Left(_) = &invoke.function {
        lowering.bump_tainted("inline_asm");
        push_unknown(
            body,
            "invoke",
            invoke
                .arguments
                .iter()
                .map(|(arg, _)| operand_value_key(func_name, arg))
                .collect(),
            vec![local_value_key(func_name, &invoke.result)],
            "inline_asm",
            loc(invoke.debugloc.as_ref()),
            lowering,
        );
        return;
    }

    if let Some(callee) = called_function_name(&invoke.function) {
        if ifunc_names.contains(&callee) {
            lower_ifunc_call(
                func_name,
                "invoke",
                &callee,
                &invoke.arguments,
                Some(&invoke.result),
                loc(invoke.debugloc.as_ref()),
                body,
                lowering,
            );
            return;
        }
    }

    let Some(sig) = call_signature_from_operand(
        module,
        &invoke.function,
        invoke.arguments.iter().map(|a| &a.1),
        invoke.calling_convention,
        lowering,
    ) else {
        lowering.bump_skipped("invoke_without_function_signature");
        return;
    };
    match called_function_name(&invoke.function) {
        Some(callee) if is_skipped_intrinsic(&callee) => {}
        Some(callee) if resolve_function_name(&callee, func_names, aliases).is_some() => {
            let resolved = resolve_function_name(&callee, func_names, aliases).unwrap();
            if resolved != callee {
                lowering.bump_modeled("alias_call_direct");
            }
            body.push(Stmt::CallDirect {
                callee: resolved,
                sig,
                loc: loc(invoke.debugloc.as_ref()),
            });
            lowering.bump_modeled("call_direct");
        }
        _ => {
            body.push(Stmt::CallIndirect {
                operand: operand_key_either(func_name, &invoke.function),
                sig,
                loc: loc(invoke.debugloc.as_ref()),
            });
            lowering.bump_modeled("call_indirect");
        }
    }
    bump_missing_loc(lowering, "invoke", invoke.debugloc.as_ref());
}

fn lower_ifunc_call(
    func_name: &str,
    op: &str,
    callee: &str,
    arguments: &[(Operand, Vec<ParameterAttribute>)],
    dest: Option<&Name>,
    loc: Option<Loc>,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    lowering.bump_tainted(format!("ifunc_callee:{callee}"));
    push_unknown(
        body,
        op,
        arguments
            .iter()
            .map(|(arg, _)| operand_value_key(func_name, arg))
            .collect(),
        dest.map(|dest| vec![local_value_key(func_name, dest)])
            .unwrap_or_default(),
        "ifunc_callee",
        loc,
        lowering,
    );
}

fn lower_load(
    func_name: &str,
    load: &Load,
    global_names: &BTreeSet<String>,
    aliases: &AliasMap,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    body.push(Stmt::Load {
        dest: local_value_key(func_name, &load.dest),
        address: operand_value_key(func_name, &load.address),
        loc: loc(load.debugloc.as_ref()),
    });
    lowering.bump_modeled("load");
    bump_missing_loc(lowering, "load", load.debugloc.as_ref());
    if load.volatile {
        lowering.bump_modeled("volatile_load");
    }
    if load.atomicity.is_some() {
        lowering.bump_modeled("atomic_load");
    }
    if let Some(global) = operand_global_name(&load.address)
        .and_then(|name| resolve_global_alias(&name, aliases).or(Some(name)))
        .filter(|name| global_names.contains(name))
    {
        body.push(Stmt::GlobalRef {
            global,
            access: Access::Ref,
            loc: loc(load.debugloc.as_ref()),
        });
        lowering.bump_modeled("global_ref");
    }
}

fn lower_store(
    func_name: &str,
    store: &Store,
    global_names: &BTreeSet<String>,
    aliases: &AliasMap,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    body.push(Stmt::Store {
        address: operand_value_key(func_name, &store.address),
        value: operand_value_key(func_name, &store.value),
        loc: loc(store.debugloc.as_ref()),
    });
    lowering.bump_modeled("store");
    bump_missing_loc(lowering, "store", store.debugloc.as_ref());
    if store.volatile {
        lowering.bump_modeled("volatile_store");
    }
    if store.atomicity.is_some() {
        lowering.bump_modeled("atomic_store");
    }
    if let Some(global) = operand_global_name(&store.address)
        .and_then(|name| resolve_global_alias(&name, aliases).or(Some(name)))
        .filter(|name| global_names.contains(name))
    {
        body.push(Stmt::GlobalRef {
            global,
            access: Access::Mod,
            loc: loc(store.debugloc.as_ref()),
        });
        lowering.bump_modeled("global_mod");
    }
}

fn lower_cmpxchg(
    func_name: &str,
    cmpxchg: &CmpXchg,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    body.push(Stmt::Load {
        dest: format!("{}.old", local_value_key(func_name, &cmpxchg.dest)),
        address: operand_value_key(func_name, &cmpxchg.address),
        loc: loc(cmpxchg.debugloc.as_ref()),
    });
    body.push(Stmt::Store {
        address: operand_value_key(func_name, &cmpxchg.address),
        value: operand_value_key(func_name, &cmpxchg.replacement),
        loc: loc(cmpxchg.debugloc.as_ref()),
    });
    lowering.bump_modeled("cmpxchg");
    lowering.bump_modeled("atomic_load");
    lowering.bump_modeled("atomic_store");
    if cmpxchg.volatile {
        lowering.bump_modeled("volatile_cmpxchg");
    }
    bump_missing_loc(lowering, "cmpxchg", cmpxchg.debugloc.as_ref());
}

fn lower_atomicrmw(
    func_name: &str,
    atomicrmw: &AtomicRMW,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    body.push(Stmt::Load {
        dest: local_value_key(func_name, &atomicrmw.dest),
        address: operand_value_key(func_name, &atomicrmw.address),
        loc: loc(atomicrmw.debugloc.as_ref()),
    });
    body.push(Stmt::Store {
        address: operand_value_key(func_name, &atomicrmw.address),
        value: operand_value_key(func_name, &atomicrmw.value),
        loc: loc(atomicrmw.debugloc.as_ref()),
    });
    lowering.bump_modeled("atomicrmw");
    lowering.bump_modeled("atomic_load");
    lowering.bump_modeled("atomic_store");
    if atomicrmw.volatile {
        lowering.bump_modeled("volatile_atomicrmw");
    }
    bump_missing_loc(lowering, "atomicrmw", atomicrmw.debugloc.as_ref());
}

fn lower_gep(
    module: &Module,
    func_name: &str,
    gep: &GetElementPtr,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    body.push(Stmt::Gep {
        dest: local_value_key(func_name, &gep.dest),
        base: operand_value_key(func_name, &gep.address),
        byte_off: gep_byte_offset(module, &gep.source_element_type, &gep.indices, lowering),
        loc: loc(gep.debugloc.as_ref()),
    });
    lowering.bump_modeled("gep");
    bump_missing_loc(lowering, "gep", gep.debugloc.as_ref());
}

fn lower_ptr_to_int(
    func_name: &str,
    cast: &PtrToInt,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    body.push(Stmt::PtrToInt {
        dest: local_value_key(func_name, &cast.dest),
        source: operand_value_key(func_name, &cast.operand),
        loc: loc(cast.debugloc.as_ref()),
    });
    lowering.bump_modeled("ptrtoint");
    bump_missing_loc(lowering, "ptrtoint", cast.debugloc.as_ref());
}

fn lower_int_to_ptr(
    func_name: &str,
    cast: &IntToPtr,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    body.push(Stmt::IntToPtr {
        dest: local_value_key(func_name, &cast.dest),
        source: operand_value_key(func_name, &cast.operand),
        loc: loc(cast.debugloc.as_ref()),
    });
    lowering.bump_tainted("inttoptr");
    lowering.bump_modeled("inttoptr");
    bump_missing_loc(lowering, "inttoptr", cast.debugloc.as_ref());
}

fn lower_bitcast(
    module: &Module,
    func_name: &str,
    cast: &BitCast,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    if operand_has_pointer_type(module, &cast.operand) || is_pointer_like_type(&cast.to_type) {
        body.push(Stmt::Assign {
            dest: local_value_key(func_name, &cast.dest),
            sources: vec![operand_value_key(func_name, &cast.operand)],
            loc: loc(cast.debugloc.as_ref()),
        });
        lowering.bump_modeled("assign");
    } else {
        lowering.bump_skipped("bitcast_non_pointer");
    }
    bump_missing_loc(lowering, "bitcast", cast.debugloc.as_ref());
}

fn lower_addrspacecast(
    module: &Module,
    func_name: &str,
    cast: &AddrSpaceCast,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    if operand_has_pointer_type(module, &cast.operand) || is_pointer_like_type(&cast.to_type) {
        body.push(Stmt::Assign {
            dest: local_value_key(func_name, &cast.dest),
            sources: vec![operand_value_key(func_name, &cast.operand)],
            loc: loc(cast.debugloc.as_ref()),
        });
        lowering.bump_modeled("assign");
    } else {
        lowering.bump_skipped("addrspacecast_non_pointer");
    }
    bump_missing_loc(lowering, "addrspacecast", cast.debugloc.as_ref());
}

fn lower_phi(
    module: &Module,
    func_name: &str,
    phi: &Phi,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    if is_pointer_like_type(&phi.to_type) {
        body.push(Stmt::Assign {
            dest: local_value_key(func_name, &phi.dest),
            sources: phi
                .incoming_values
                .iter()
                .map(|(op, _)| operand_value_key(func_name, op))
                .collect(),
            loc: loc(phi.debugloc.as_ref()),
        });
        lowering.bump_modeled("assign");
    } else if phi
        .incoming_values
        .iter()
        .any(|(op, _)| operand_has_pointer_type(module, op))
    {
        lowering.bump_tainted("phi_pointer_operand_non_pointer_result");
    } else {
        lowering.bump_skipped("phi_non_pointer");
    }
    bump_missing_loc(lowering, "phi", phi.debugloc.as_ref());
}

fn lower_select(
    module: &Module,
    func_name: &str,
    select: &Select,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    if operand_has_pointer_type(module, &select.true_value)
        || operand_has_pointer_type(module, &select.false_value)
    {
        body.push(Stmt::Assign {
            dest: local_value_key(func_name, &select.dest),
            sources: vec![
                operand_value_key(func_name, &select.true_value),
                operand_value_key(func_name, &select.false_value),
            ],
            loc: loc(select.debugloc.as_ref()),
        });
        lowering.bump_modeled("assign");
    } else {
        lowering.bump_skipped("select_non_pointer");
    }
    bump_missing_loc(lowering, "select", select.debugloc.as_ref());
}

fn lower_freeze(
    func_name: &str,
    freeze: &Freeze,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    body.push(Stmt::Assign {
        dest: local_value_key(func_name, &freeze.dest),
        sources: vec![operand_value_key(func_name, &freeze.operand)],
        loc: loc(freeze.debugloc.as_ref()),
    });
    lowering.bump_modeled("assign");
    bump_missing_loc(lowering, "freeze", freeze.debugloc.as_ref());
}

fn lower_personality_function(
    module: &Module,
    function: &Function,
    aliases: &AliasMap,
    lowering: &mut LoweringStats,
) {
    let Some(personality) = &function.personality_function else {
        return;
    };
    if constant_has_pointer_flow(module, personality) {
        lowering.bump_tainted("personality_function");
        for operand in constant_pointer_operand_keys(module, personality, aliases) {
            lowering.bump_tainted(format!("personality_operand:{operand}"));
        }
    }
}

fn lower_extract_element(
    module: &Module,
    func_name: &str,
    extract: &ExtractElement,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    if is_pointer_vector_type(&extract.vector.get_type(&module.types)) {
        lowering.bump_tainted("pointer_vector:extractelement");
        push_unknown(
            body,
            "extractelement",
            vec![
                operand_value_key(func_name, &extract.vector),
                operand_value_key(func_name, &extract.index),
            ],
            vec![local_value_key(func_name, &extract.dest)],
            "pointer_vector",
            loc(extract.debugloc.as_ref()),
            lowering,
        );
    } else {
        lowering.bump_skipped("extractelement_non_pointer_vector");
    }
    bump_missing_loc(lowering, "extractelement", extract.debugloc.as_ref());
}

fn lower_insert_element(
    module: &Module,
    func_name: &str,
    insert: &InsertElement,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    if is_pointer_vector_type(&insert.vector.get_type(&module.types))
        || operand_has_pointer_type(module, &insert.element)
    {
        lowering.bump_tainted("pointer_vector:insertelement");
        push_unknown(
            body,
            "insertelement",
            vec![
                operand_value_key(func_name, &insert.vector),
                operand_value_key(func_name, &insert.element),
                operand_value_key(func_name, &insert.index),
            ],
            vec![local_value_key(func_name, &insert.dest)],
            "pointer_vector",
            loc(insert.debugloc.as_ref()),
            lowering,
        );
    } else {
        lowering.bump_skipped("insertelement_non_pointer_vector");
    }
    bump_missing_loc(lowering, "insertelement", insert.debugloc.as_ref());
}

fn lower_shuffle_vector(
    module: &Module,
    func_name: &str,
    shuffle: &ShuffleVector,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    if is_pointer_vector_type(&shuffle.operand0.get_type(&module.types))
        || is_pointer_vector_type(&shuffle.operand1.get_type(&module.types))
        || is_pointer_vector_type(&shuffle.get_type(&module.types))
    {
        lowering.bump_tainted("pointer_vector:shufflevector");
        push_unknown(
            body,
            "shufflevector",
            vec![
                operand_value_key(func_name, &shuffle.operand0),
                operand_value_key(func_name, &shuffle.operand1),
                constant_value_key(&shuffle.mask),
            ],
            vec![local_value_key(func_name, &shuffle.dest)],
            "pointer_vector",
            loc(shuffle.debugloc.as_ref()),
            lowering,
        );
    } else {
        lowering.bump_skipped("shufflevector_non_pointer_vector");
    }
    bump_missing_loc(lowering, "shufflevector", shuffle.debugloc.as_ref());
}

fn lower_extract_value(
    module: &Module,
    func_name: &str,
    extract: &ExtractValue,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    let result_type = extract.get_type(&module.types);
    if is_pointer_vector_type(&result_type) {
        lowering.bump_tainted("pointer_vector:extractvalue");
        push_unknown(
            body,
            "extractvalue",
            vec![operand_value_key(func_name, &extract.aggregate)],
            vec![local_value_key(func_name, &extract.dest)],
            "pointer_vector",
            loc(extract.debugloc.as_ref()),
            lowering,
        );
    } else if is_pointer_like_type(&result_type) {
        body.push(Stmt::Assign {
            dest: local_value_key(func_name, &extract.dest),
            sources: vec![operand_value_key(func_name, &extract.aggregate)],
            loc: loc(extract.debugloc.as_ref()),
        });
        lowering.bump_modeled("extractvalue");
        lowering.bump_modeled("assign");
    } else if operand_type_contains_pointer(module, &extract.aggregate) {
        lowering.bump_tainted("extractvalue_pointer_aggregate_non_pointer_result");
    } else {
        lowering.bump_skipped("extractvalue_non_pointer");
    }
    bump_missing_loc(lowering, "extractvalue", extract.debugloc.as_ref());
}

fn lower_insert_value(
    module: &Module,
    func_name: &str,
    insert: &InsertValue,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    if type_contains_pointer(module, &insert.get_type(&module.types))
        || operand_type_contains_pointer(module, &insert.element)
    {
        body.push(Stmt::Assign {
            dest: local_value_key(func_name, &insert.dest),
            sources: vec![
                operand_value_key(func_name, &insert.aggregate),
                operand_value_key(func_name, &insert.element),
            ],
            loc: loc(insert.debugloc.as_ref()),
        });
        lowering.bump_modeled("insertvalue");
        lowering.bump_modeled("assign");
        lowering.bump_tainted("insertvalue_coarse");
    } else {
        lowering.bump_skipped("insertvalue_non_pointer");
    }
    bump_missing_loc(lowering, "insertvalue", insert.debugloc.as_ref());
}

fn lower_landingpad(
    module: &Module,
    func_name: &str,
    landingpad: &LandingPad,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    if type_contains_pointer(module, &landingpad.result_type) {
        lowering.bump_tainted("landingpad_pointer_result");
        push_unknown(
            body,
            "landingpad",
            Vec::new(),
            vec![local_value_key(func_name, &landingpad.dest)],
            "landingpad_pointer_result",
            loc(landingpad.debugloc.as_ref()),
            lowering,
        );
    } else {
        lowering.bump_skipped("landingpad_non_pointer");
    }
    bump_missing_loc(lowering, "landingpad", landingpad.debugloc.as_ref());
}

fn lower_intrinsic_call(
    module: &Module,
    func_name: &str,
    callee: &str,
    call: &Call,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) -> bool {
    if !callee.starts_with("llvm.") {
        return false;
    }

    if is_skipped_intrinsic(callee)
        || callee.starts_with("llvm.lifetime.")
        || callee == "llvm.assume"
        || callee.starts_with("llvm.expect.")
        || callee.starts_with("llvm.annotation.")
        || callee.starts_with("llvm.prefetch.")
    {
        lowering.bump_skipped(format!("intrinsic:{callee}"));
        return true;
    }

    if callee.starts_with("llvm.memcpy.") || callee.starts_with("llvm.memmove.") {
        if call.arguments.len() >= 3 {
            body.push(Stmt::Memcpy {
                dst: operand_value_key(func_name, &call.arguments[0].0),
                src: operand_value_key(func_name, &call.arguments[1].0),
                bytes: constant_int(&call.arguments[2].0),
                loc: loc(call.debugloc.as_ref()),
            });
            lowering.bump_modeled(if callee.starts_with("llvm.memmove.") {
                "memmove"
            } else {
                "memcpy"
            });
            bump_missing_loc(lowering, "memcpy", call.debugloc.as_ref());
        } else {
            lowering.bump_tainted("malformed_memory_intrinsic");
        }
        return true;
    }

    if callee.starts_with("llvm.memset.") {
        if call.arguments.len() >= 3 {
            body.push(Stmt::Memset {
                dst: operand_value_key(func_name, &call.arguments[0].0),
                value: operand_value_key(func_name, &call.arguments[1].0),
                bytes: constant_int(&call.arguments[2].0),
                loc: loc(call.debugloc.as_ref()),
            });
            lowering.bump_modeled("memset");
            bump_missing_loc(lowering, "memset", call.debugloc.as_ref());
        } else {
            lowering.bump_tainted("malformed_memory_intrinsic");
        }
        return true;
    }

    if callee.starts_with("llvm.va_") {
        lowering.bump_tainted(format!("intrinsic:{callee}"));
        push_unknown(
            body,
            callee,
            call.arguments
                .iter()
                .map(|(arg, _)| operand_value_key(func_name, arg))
                .collect(),
            call.dest
                .as_ref()
                .map(|dest| vec![local_value_key(func_name, dest)])
                .unwrap_or_default(),
            "varargs_intrinsic",
            loc(call.debugloc.as_ref()),
            lowering,
        );
        return true;
    }

    if call
        .arguments
        .iter()
        .any(|(arg, _)| operand_has_pointer_type(module, arg))
        || call.dest.is_some() && is_pointer_like_type(&call.get_type(&module.types))
    {
        lowering.bump_tainted(format!("unknown_pointer_intrinsic:{callee}"));
        push_unknown(
            body,
            callee,
            call.arguments
                .iter()
                .map(|(arg, _)| operand_value_key(func_name, arg))
                .collect(),
            call.dest
                .as_ref()
                .map(|dest| vec![local_value_key(func_name, dest)])
                .unwrap_or_default(),
            "unknown_pointer_intrinsic",
            loc(call.debugloc.as_ref()),
            lowering,
        );
    } else {
        lowering.bump_skipped(format!("unknown_non_pointer_intrinsic:{callee}"));
    }
    true
}

fn call_signature_from_operand<'a>(
    module: &Module,
    function: &Either<InlineAssembly, Operand>,
    arg_attrs: impl Iterator<Item = &'a Vec<ParameterAttribute>>,
    cc: CallingConvention,
    lowering: &mut LoweringStats,
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
        module,
        result_type,
        param_types.iter().zip(arg_attrs),
        *is_var_arg,
        cc,
        lowering,
    ))
}

fn signature<'a, 'b>(
    module: &Module,
    ret: &TypeRef,
    params: impl Iterator<Item = (&'a TypeRef, &'b Vec<ParameterAttribute>)>,
    vararg: bool,
    cc: CallingConvention,
    lowering: &mut LoweringStats,
) -> Signature {
    let cc = cc_key(cc);
    if cc != "ccc" {
        lowering.bump_non_ccc(cc.clone());
    }
    Signature {
        ret: abi_class(ret),
        params: params
            .map(|(ty, attrs)| param_class(module, ty, attrs))
            .collect::<Vec<_>>(),
        vararg,
        cc,
    }
}

fn param_class(module: &Module, ty: &TypeRef, attrs: &[ParameterAttribute]) -> Param {
    for attr in attrs {
        match attr {
            ParameterAttribute::ByVal(ty) => {
                return Param::Byval {
                    size: type_size_key(module, ty),
                }
            }
            ParameterAttribute::SRet(ty) => {
                return Param::Sret {
                    size: type_size_key(module, ty),
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

fn type_size_key(module: &Module, ty: &TypeRef) -> u64 {
    if let Some(size) = type_alloc_size(module, ty) {
        return size;
    }
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
        } => type_size_key(module, element_type).saturating_mul(*num_elements as u64),
        Type::StructType { element_types, .. } => element_types
            .iter()
            .map(|ty| type_size_key(module, ty))
            .sum(),
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

fn resolve_function_name(
    name: &str,
    func_names: &BTreeSet<String>,
    aliases: &AliasMap,
) -> Option<String> {
    if func_names.contains(name) {
        Some(name.to_string())
    } else {
        resolve_function_alias(name, aliases)
    }
}

fn resolve_function_alias(name: &str, aliases: &AliasMap) -> Option<String> {
    match aliases.get(name) {
        Some(AliasTarget::Function(target)) => Some(target.clone()),
        _ => None,
    }
}

fn resolve_global_alias(name: &str, aliases: &AliasMap) -> Option<String> {
    match aliases.get(name) {
        Some(AliasTarget::Global(target)) => Some(target.clone()),
        _ => None,
    }
}

fn resolve_symbol_alias(name: &str, aliases: &AliasMap) -> Option<String> {
    match aliases.get(name) {
        Some(AliasTarget::Function(target)) | Some(AliasTarget::Global(target)) => {
            Some(target.clone())
        }
        None => None,
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

fn operand_key_either(func_name: &str, function: &Either<InlineAssembly, Operand>) -> String {
    match function {
        Either::Left(_) => "inline_asm".to_string(),
        Either::Right(operand) => operand_value_key(func_name, operand),
    }
}

fn local_value_key(func_name: &str, name: &Name) -> String {
    format!("%{func_name}::{}", name_key(name))
}

fn operand_value_key(func_name: &str, operand: &Operand) -> String {
    match operand {
        Operand::LocalOperand { name, .. } => local_value_key(func_name, name),
        Operand::ConstantOperand(cref) => constant_value_key(cref),
        Operand::MetadataOperand => "!metadata".to_string(),
    }
}

fn constant_value_key(constant: &Constant) -> String {
    match constant {
        Constant::GlobalReference { name, .. } => format!("@{}", name_key(name)),
        Constant::BitCast(expr) => constant_value_key(&expr.operand),
        Constant::GetElementPtr(expr) => constant_value_key(&expr.address),
        _ => constant.to_string(),
    }
}

fn constant_int(operand: &Operand) -> Option<u64> {
    match operand.as_constant()? {
        Constant::Int { value, .. } => Some(*value),
        _ => None,
    }
}

fn gep_byte_offset(
    module: &Module,
    source_element_type: &TypeRef,
    indices: &[Operand],
    lowering: &mut LoweringStats,
) -> Option<i64> {
    let indices = indices
        .iter()
        .map(constant_i64_from_operand)
        .collect::<Option<Vec<_>>>();
    let Some(indices) = indices else {
        lowering.bump_skipped("gep_dynamic_index");
        return None;
    };
    let result = gep_offset_from_indices(module, source_element_type, &indices);
    if result.is_some() {
        lowering.bump_modeled("gep_byte_offset");
    } else {
        lowering.bump_skipped("gep_unsupported_offset");
    }
    result
}

fn constant_gep_byte_offset(
    module: &Module,
    gep: &llvm_ir::constant::GetElementPtr,
    lowering: &mut LoweringStats,
) -> Option<i64> {
    let Some(source_element_type) = pointer_pointee_type(&gep.address.get_type(&module.types))
    else {
        lowering.bump_skipped("constant_gep_non_pointer_base");
        return None;
    };
    let indices = gep
        .indices
        .iter()
        .map(constant_i64)
        .collect::<Option<Vec<_>>>();
    let Some(indices) = indices else {
        lowering.bump_skipped("constant_gep_dynamic_index");
        return None;
    };
    let result = gep_offset_from_indices(module, &source_element_type, &indices);
    if result.is_some() {
        lowering.bump_modeled("global_init_gep_byte_offset");
    } else {
        lowering.bump_skipped("constant_gep_unsupported_offset");
    }
    result
}

fn gep_offset_from_indices(
    module: &Module,
    source_element_type: &TypeRef,
    indices: &[i64],
) -> Option<i64> {
    let mut offset = 0_i128;
    let mut current = source_element_type.clone();

    for (idx_pos, index) in indices.iter().copied().enumerate() {
        if idx_pos == 0 {
            let size = i128::from(type_alloc_size(module, &current)?);
            offset = offset.checked_add(i128::from(index).checked_mul(size)?)?;
            continue;
        }

        current = resolve_named_type(module, &current)?;
        match current.as_ref() {
            Type::ArrayType { element_type, .. } => {
                let stride = i128::from(type_alloc_size(module, element_type)?);
                offset = offset.checked_add(i128::from(index).checked_mul(stride)?)?;
                current = element_type.clone();
            }
            Type::StructType {
                element_types,
                is_packed,
            } => {
                if index < 0 {
                    return None;
                }
                let field_index = usize::try_from(index).ok()?;
                if field_index >= element_types.len() {
                    return None;
                }
                offset = offset.checked_add(i128::from(struct_field_offset(
                    module,
                    element_types,
                    *is_packed,
                    field_index,
                )?))?;
                current = element_types[field_index].clone();
            }
            Type::VectorType {
                element_type,
                scalable,
                ..
            } => {
                if *scalable {
                    return None;
                }
                let stride = i128::from(type_alloc_size(module, element_type)?);
                offset = offset.checked_add(i128::from(index).checked_mul(stride)?)?;
                current = element_type.clone();
            }
            _ => return None,
        }
    }

    i64::try_from(offset).ok()
}

fn struct_field_offset(
    module: &Module,
    element_types: &[TypeRef],
    is_packed: bool,
    field_index: usize,
) -> Option<u64> {
    let mut offset = 0_u64;
    for (idx, element_type) in element_types.iter().enumerate() {
        if !is_packed {
            offset = align_to(offset, type_abi_align(module, element_type)?)?;
        }
        if idx == field_index {
            return Some(offset);
        }
        offset = offset.checked_add(type_alloc_size(module, element_type)?)?;
    }
    None
}

fn type_alloc_size(module: &Module, ty: &TypeRef) -> Option<u64> {
    let ty = resolve_named_type(module, ty)?;
    let store_size = type_store_size(module, &ty)?;
    let align = type_abi_align(module, &ty)?;
    align_to(store_size, align)
}

fn type_store_size(module: &Module, ty: &TypeRef) -> Option<u64> {
    let ty = resolve_named_type(module, ty)?;
    match ty.as_ref() {
        Type::VoidType => Some(0),
        Type::IntegerType { bits } => Some(u64::from(*bits).div_ceil(8)),
        Type::PointerType { addr_space, .. } => Some(u64::from(
            module
                .data_layout
                .alignments
                .ptr_alignment(*addr_space)
                .size
                .div_ceil(8),
        )),
        Type::FPType(fpt) => Some(u64::from(fp_size_bits(*fpt).div_ceil(8))),
        Type::ArrayType {
            element_type,
            num_elements,
        } => type_alloc_size(module, element_type)?.checked_mul(*num_elements as u64),
        Type::StructType {
            element_types,
            is_packed,
        } => {
            let mut offset = 0_u64;
            let mut max_align = 1_u64;
            for element_type in element_types {
                let align = if *is_packed {
                    1
                } else {
                    type_abi_align(module, element_type)?
                };
                max_align = max_align.max(align);
                offset = align_to(offset, align)?;
                offset = offset.checked_add(type_alloc_size(module, element_type)?)?;
            }
            if *is_packed {
                Some(offset)
            } else {
                align_to(offset, max_align)
            }
        }
        Type::VectorType {
            element_type,
            num_elements,
            scalable,
        } => {
            if *scalable {
                None
            } else {
                type_store_size(module, element_type)?.checked_mul(*num_elements as u64)
            }
        }
        Type::FuncType { .. } => None,
        Type::NamedStructType { .. } => unreachable!("named structs are resolved above"),
        Type::X86_MMXType => Some(8),
        Type::X86_AMXType => None,
        Type::MetadataType | Type::LabelType | Type::TokenType => None,
    }
}

fn type_abi_align(module: &Module, ty: &TypeRef) -> Option<u64> {
    let ty = resolve_named_type(module, ty)?;
    match ty.as_ref() {
        Type::VoidType => Some(1),
        Type::StructType {
            element_types,
            is_packed,
        } => {
            if *is_packed {
                Some(1)
            } else {
                element_types
                    .iter()
                    .try_fold(1_u64, |max_align, element_type| {
                        Some(max_align.max(type_abi_align(module, element_type)?))
                    })
            }
        }
        Type::ArrayType { element_type, .. } => type_abi_align(module, element_type),
        Type::FuncType { .. } => None,
        Type::MetadataType | Type::LabelType | Type::TokenType | Type::X86_AMXType => None,
        _ => Some(
            u64::from(
                module
                    .data_layout
                    .alignments
                    .type_alignment(ty.as_ref())
                    .abi
                    .div_ceil(8),
            )
            .max(1),
        ),
    }
}

fn resolve_named_type(module: &Module, ty: &TypeRef) -> Option<TypeRef> {
    match ty.as_ref() {
        Type::NamedStructType { name } => match module.types.named_struct_def(name)? {
            NamedStructDef::Defined(ty) => Some(ty.clone()),
            NamedStructDef::Opaque => None,
        },
        _ => Some(ty.clone()),
    }
}

fn pointer_pointee_type(ty: &TypeRef) -> Option<TypeRef> {
    match ty.as_ref() {
        Type::PointerType { pointee_type, .. } => Some(pointee_type.clone()),
        _ => None,
    }
}

fn align_to(value: u64, align: u64) -> Option<u64> {
    if align <= 1 {
        return Some(value);
    }
    let remainder = value % align;
    if remainder == 0 {
        Some(value)
    } else {
        value.checked_add(align - remainder)
    }
}

fn fp_size_bits(fpt: FPType) -> u32 {
    match fpt {
        FPType::Half => 16,
        FPType::BFloat => 16,
        FPType::Single => 32,
        FPType::Double => 64,
        FPType::FP128 => 128,
        FPType::X86_FP80 => 80,
        FPType::PPC_FP128 => 128,
    }
}

fn constant_i64_from_operand(operand: &Operand) -> Option<i64> {
    constant_i64_value(operand.as_constant()?)
}

fn constant_i64(constant: &ConstantRef) -> Option<i64> {
    constant_i64_value(constant.as_ref())
}

fn constant_i64_value(constant: &Constant) -> Option<i64> {
    let Constant::Int { bits, value } = constant else {
        return None;
    };
    if *bits == 0 || *bits > 64 {
        return None;
    }
    let sign_bit = 1_u64.checked_shl(bits - 1)?;
    if value & sign_bit == 0 {
        i64::try_from(*value).ok()
    } else if *bits == 64 {
        Some(*value as i64)
    } else {
        let extended = value | (!0_u64).checked_shl(*bits)?;
        Some(extended as i64)
    }
}

fn global_init_temp(temp_ordinal: &mut u64) -> String {
    let value = format!("@__global_init::{}", *temp_ordinal);
    *temp_ordinal += 1;
    value
}

fn constant_has_pointer_flow(module: &Module, constant: &Constant) -> bool {
    match constant {
        Constant::GlobalReference { .. } => true,
        Constant::Struct { values, .. }
        | Constant::Array {
            elements: values, ..
        }
        | Constant::Vector(values) => values
            .iter()
            .any(|value| constant_has_pointer_flow(module, value)),
        Constant::BitCast(expr) => {
            constant_has_pointer_flow(module, &expr.operand) || is_pointer_like_type(&expr.to_type)
        }
        Constant::AddrSpaceCast(expr) => {
            constant_has_pointer_flow(module, &expr.operand) || is_pointer_like_type(&expr.to_type)
        }
        Constant::GetElementPtr(_) => true,
        Constant::PtrToInt(expr) => constant_has_pointer_flow(module, &expr.operand),
        Constant::IntToPtr(_) => true,
        Constant::ExtractElement(expr) => constant_has_pointer_flow(module, &expr.vector),
        Constant::InsertElement(expr) => {
            constant_has_pointer_flow(module, &expr.vector)
                || constant_has_pointer_flow(module, &expr.element)
        }
        Constant::ShuffleVector(expr) => {
            constant_has_pointer_flow(module, &expr.operand0)
                || constant_has_pointer_flow(module, &expr.operand1)
        }
        Constant::ExtractValue(expr) => constant_has_pointer_flow(module, &expr.aggregate),
        Constant::InsertValue(expr) => {
            constant_has_pointer_flow(module, &expr.aggregate)
                || constant_has_pointer_flow(module, &expr.element)
        }
        Constant::Select(expr) => {
            constant_has_pointer_flow(module, &expr.true_value)
                || constant_has_pointer_flow(module, &expr.false_value)
        }
        Constant::Null(_) | Constant::AggregateZero(_) | Constant::Undef(_) => false,
        Constant::Poison(_) => false,
        _ => is_pointer_like_type(&constant.get_type(&module.types)),
    }
}

fn constant_pointer_operand_keys(
    module: &Module,
    constant: &Constant,
    aliases: &AliasMap,
) -> Vec<String> {
    let mut values = BTreeSet::new();
    collect_constant_pointer_operand_keys(module, constant, aliases, &mut values);
    values.into_iter().collect()
}

fn collect_constant_pointer_operand_keys(
    module: &Module,
    constant: &Constant,
    aliases: &AliasMap,
    out: &mut BTreeSet<String>,
) {
    match constant {
        Constant::GlobalReference { name, .. } => {
            let name = name_key(name);
            out.insert(format!(
                "@{}",
                resolve_symbol_alias(&name, aliases).unwrap_or(name)
            ));
        }
        Constant::Struct { values, .. }
        | Constant::Array {
            elements: values, ..
        }
        | Constant::Vector(values) => {
            for value in values {
                collect_constant_pointer_operand_keys(module, value, aliases, out);
            }
        }
        Constant::BitCast(expr) => {
            collect_constant_pointer_operand_keys(module, &expr.operand, aliases, out);
        }
        Constant::AddrSpaceCast(expr) => {
            collect_constant_pointer_operand_keys(module, &expr.operand, aliases, out);
        }
        Constant::GetElementPtr(expr) => {
            collect_constant_pointer_operand_keys(module, &expr.address, aliases, out);
            for index in &expr.indices {
                collect_constant_pointer_operand_keys(module, index, aliases, out);
            }
        }
        Constant::PtrToInt(expr) => {
            collect_constant_pointer_operand_keys(module, &expr.operand, aliases, out);
        }
        Constant::IntToPtr(expr) => {
            collect_constant_pointer_operand_keys(module, &expr.operand, aliases, out);
        }
        Constant::ExtractElement(expr) => {
            collect_constant_pointer_operand_keys(module, &expr.vector, aliases, out);
            collect_constant_pointer_operand_keys(module, &expr.index, aliases, out);
        }
        Constant::InsertElement(expr) => {
            collect_constant_pointer_operand_keys(module, &expr.vector, aliases, out);
            collect_constant_pointer_operand_keys(module, &expr.element, aliases, out);
            collect_constant_pointer_operand_keys(module, &expr.index, aliases, out);
        }
        Constant::ShuffleVector(expr) => {
            collect_constant_pointer_operand_keys(module, &expr.operand0, aliases, out);
            collect_constant_pointer_operand_keys(module, &expr.operand1, aliases, out);
            collect_constant_pointer_operand_keys(module, &expr.mask, aliases, out);
        }
        Constant::ExtractValue(expr) => {
            collect_constant_pointer_operand_keys(module, &expr.aggregate, aliases, out);
        }
        Constant::InsertValue(expr) => {
            collect_constant_pointer_operand_keys(module, &expr.aggregate, aliases, out);
            collect_constant_pointer_operand_keys(module, &expr.element, aliases, out);
        }
        Constant::Select(expr) => {
            collect_constant_pointer_operand_keys(module, &expr.condition, aliases, out);
            collect_constant_pointer_operand_keys(module, &expr.true_value, aliases, out);
            collect_constant_pointer_operand_keys(module, &expr.false_value, aliases, out);
        }
        _ if is_pointer_like_type(&constant.get_type(&module.types)) => {
            out.insert(constant_value_key(constant));
        }
        _ => {}
    }
}

fn constant_opcode(constant: &Constant) -> &'static str {
    match constant {
        Constant::Int { .. } => "int",
        Constant::Float(_) => "float",
        Constant::Null(_) => "null",
        Constant::AggregateZero(_) => "aggregate_zero",
        Constant::Struct { .. } => "struct",
        Constant::Array { .. } => "array",
        Constant::Vector(_) => "vector",
        Constant::Undef(_) => "undef",
        Constant::Poison(_) => "poison",
        Constant::BlockAddress => "block_address",
        Constant::GlobalReference { .. } => "global_reference",
        Constant::TokenNone => "token_none",
        Constant::Add(_) => "add",
        Constant::Sub(_) => "sub",
        Constant::Mul(_) => "mul",
        Constant::UDiv(_) => "udiv",
        Constant::SDiv(_) => "sdiv",
        Constant::URem(_) => "urem",
        Constant::SRem(_) => "srem",
        Constant::And(_) => "and",
        Constant::Or(_) => "or",
        Constant::Xor(_) => "xor",
        Constant::Shl(_) => "shl",
        Constant::LShr(_) => "lshr",
        Constant::AShr(_) => "ashr",
        Constant::FAdd(_) => "fadd",
        Constant::FSub(_) => "fsub",
        Constant::FMul(_) => "fmul",
        Constant::FDiv(_) => "fdiv",
        Constant::FRem(_) => "frem",
        Constant::ExtractElement(_) => "extractelement",
        Constant::InsertElement(_) => "insertelement",
        Constant::ShuffleVector(_) => "shufflevector",
        Constant::ExtractValue(_) => "extractvalue",
        Constant::InsertValue(_) => "insertvalue",
        Constant::GetElementPtr(_) => "getelementptr",
        Constant::Trunc(_) => "trunc",
        Constant::ZExt(_) => "zext",
        Constant::SExt(_) => "sext",
        Constant::FPTrunc(_) => "fptrunc",
        Constant::FPExt(_) => "fpext",
        Constant::FPToUI(_) => "fptoui",
        Constant::FPToSI(_) => "fptosi",
        Constant::UIToFP(_) => "uitofp",
        Constant::SIToFP(_) => "sitofp",
        Constant::PtrToInt(_) => "ptrtoint",
        Constant::IntToPtr(_) => "inttoptr",
        Constant::BitCast(_) => "bitcast",
        Constant::AddrSpaceCast(_) => "addrspacecast",
        Constant::ICmp(_) => "icmp",
        Constant::FCmp(_) => "fcmp",
        Constant::Select(_) => "select",
    }
}

fn operand_has_pointer_type(module: &Module, operand: &Operand) -> bool {
    is_pointer_like_type(&operand.get_type(&module.types))
}

fn operand_type_contains_pointer(module: &Module, operand: &Operand) -> bool {
    type_contains_pointer(module, &operand.get_type(&module.types))
}

fn is_pointer_like_type(ty: &TypeRef) -> bool {
    match ty.as_ref() {
        Type::PointerType { .. } => true,
        Type::VectorType { element_type, .. } => is_pointer_like_type(element_type),
        _ => false,
    }
}

fn is_pointer_vector_type(ty: &TypeRef) -> bool {
    match ty.as_ref() {
        Type::VectorType { element_type, .. } => type_contains_pointer_shallow(element_type),
        _ => false,
    }
}

fn type_contains_pointer(module: &Module, ty: &TypeRef) -> bool {
    let Some(ty) = resolve_named_type(module, ty) else {
        return false;
    };
    match ty.as_ref() {
        Type::PointerType { .. } => true,
        Type::ArrayType { element_type, .. } | Type::VectorType { element_type, .. } => {
            type_contains_pointer(module, element_type)
        }
        Type::StructType { element_types, .. } => element_types
            .iter()
            .any(|element_type| type_contains_pointer(module, element_type)),
        _ => false,
    }
}

fn type_contains_pointer_shallow(ty: &TypeRef) -> bool {
    match ty.as_ref() {
        Type::PointerType { .. } => true,
        Type::VectorType { element_type, .. } => type_contains_pointer_shallow(element_type),
        _ => false,
    }
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

fn bump_missing_loc(lowering: &mut LoweringStats, kind: &str, loc: Option<&DebugLoc>) {
    if loc.is_none() {
        lowering.bump_missing_debug_location(kind);
    }
}

fn instruction_opcode(instr: &Instruction) -> &'static str {
    match instr {
        Instruction::Add(_) => "add",
        Instruction::Sub(_) => "sub",
        Instruction::Mul(_) => "mul",
        Instruction::UDiv(_) => "udiv",
        Instruction::SDiv(_) => "sdiv",
        Instruction::URem(_) => "urem",
        Instruction::SRem(_) => "srem",
        Instruction::And(_) => "and",
        Instruction::Or(_) => "or",
        Instruction::Xor(_) => "xor",
        Instruction::Shl(_) => "shl",
        Instruction::LShr(_) => "lshr",
        Instruction::AShr(_) => "ashr",
        Instruction::FAdd(_) => "fadd",
        Instruction::FSub(_) => "fsub",
        Instruction::FMul(_) => "fmul",
        Instruction::FDiv(_) => "fdiv",
        Instruction::FRem(_) => "frem",
        Instruction::FNeg(_) => "fneg",
        Instruction::ExtractElement(_) => "extractelement",
        Instruction::InsertElement(_) => "insertelement",
        Instruction::ShuffleVector(_) => "shufflevector",
        Instruction::ExtractValue(_) => "extractvalue",
        Instruction::InsertValue(_) => "insertvalue",
        Instruction::Alloca(_) => "alloca",
        Instruction::Load(_) => "load",
        Instruction::Store(_) => "store",
        Instruction::Fence(_) => "fence",
        Instruction::CmpXchg(_) => "cmpxchg",
        Instruction::AtomicRMW(_) => "atomicrmw",
        Instruction::GetElementPtr(_) => "getelementptr",
        Instruction::Trunc(_) => "trunc",
        Instruction::ZExt(_) => "zext",
        Instruction::SExt(_) => "sext",
        Instruction::FPTrunc(_) => "fptrunc",
        Instruction::FPExt(_) => "fpext",
        Instruction::FPToUI(_) => "fptoui",
        Instruction::FPToSI(_) => "fptosi",
        Instruction::UIToFP(_) => "uitofp",
        Instruction::SIToFP(_) => "sitofp",
        Instruction::PtrToInt(_) => "ptrtoint",
        Instruction::IntToPtr(_) => "inttoptr",
        Instruction::BitCast(_) => "bitcast",
        Instruction::AddrSpaceCast(_) => "addrspacecast",
        Instruction::ICmp(_) => "icmp",
        Instruction::FCmp(_) => "fcmp",
        Instruction::Phi(_) => "phi",
        Instruction::Select(_) => "select",
        Instruction::Freeze(_) => "freeze",
        Instruction::Call(_) => "call",
        Instruction::VAArg(_) => "va_arg",
        Instruction::LandingPad(_) => "landingpad",
        Instruction::CatchPad(_) => "catchpad",
        Instruction::CleanupPad(_) => "cleanuppad",
    }
}

fn terminator_opcode(term: &Terminator) -> &'static str {
    match term {
        Terminator::Ret(_) => "ret",
        Terminator::Br(_) => "br",
        Terminator::CondBr(_) => "condbr",
        Terminator::Switch(_) => "switch",
        Terminator::IndirectBr(_) => "indirectbr",
        Terminator::Invoke(_) => "invoke",
        Terminator::Resume(_) => "resume",
        Terminator::Unreachable(_) => "unreachable",
        Terminator::CleanupRet(_) => "cleanupret",
        Terminator::CatchRet(_) => "catchret",
        Terminator::CatchSwitch(_) => "catchswitch",
        Terminator::CallBr(_) => "callbr",
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

#[cfg(test)]
mod tests {
    use llvm_ir::module::{ThreadLocalMode, UnnamedAddr};

    use super::*;

    #[test]
    fn collect_aliases_resolves_local_targets_and_taints_interposable() {
        let module = Module::from_ir_str(
            r#"
@G = global i32 0
define void @target() {
entry:
  ret void
}
"#,
        )
        .unwrap();
        let func_ty = module
            .types
            .func_type(module.types.void(), Vec::new(), false);
        let func_ptr_ty = module.types.pointer_to(func_ty.clone());
        let i32_ty = module.types.i32();
        let i32_ptr_ty = module.types.pointer_to(i32_ty.clone());
        let aliases = vec![
            test_alias(
                "FAlias",
                "target",
                Linkage::Internal,
                func_ty.clone(),
                func_ptr_ty,
            ),
            test_alias(
                "GAlias",
                "G",
                Linkage::Private,
                i32_ty.clone(),
                i32_ptr_ty.clone(),
            ),
            test_alias(
                "WeakAlias",
                "target",
                Linkage::WeakAny,
                func_ty,
                i32_ptr_ty.clone(),
            ),
            test_alias(
                "MissingAlias",
                "missing",
                Linkage::Internal,
                i32_ty,
                i32_ptr_ty,
            ),
        ];
        let func_names = BTreeSet::from(["target".to_string()]);
        let global_names = BTreeSet::from(["G".to_string()]);
        let mut lowering = LoweringStats::default();

        let resolved = collect_aliases(&aliases, &func_names, &global_names, &mut lowering);

        assert_eq!(
            resolved.get("FAlias"),
            Some(&AliasTarget::Function("target".to_string()))
        );
        assert_eq!(
            resolved.get("GAlias"),
            Some(&AliasTarget::Global("G".to_string()))
        );
        assert_eq!(lowering.modeled_counts["alias_function_resolved"], 1);
        assert_eq!(lowering.modeled_counts["alias_global_resolved"], 1);
        assert_eq!(lowering.tainted_counts["alias_interposable:WeakAlias"], 1);
        assert_eq!(lowering.tainted_counts["alias_unresolved:MissingAlias"], 1);
    }

    fn test_alias(
        alias: &str,
        target: &str,
        linkage: Linkage,
        target_ty: TypeRef,
        alias_ty: TypeRef,
    ) -> GlobalAlias {
        GlobalAlias {
            name: Name::from(alias),
            aliasee: ConstantRef::new(Constant::GlobalReference {
                name: Name::from(target),
                ty: target_ty,
            }),
            linkage,
            visibility: Visibility::Default,
            ty: alias_ty,
            addr_space: 0,
            dll_storage_class: DLLStorageClass::Default,
            thread_local_mode: ThreadLocalMode::NotThreadLocal,
            unnamed_addr: None::<UnnamedAddr>,
        }
    }
}
