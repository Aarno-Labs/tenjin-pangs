use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::{Component, Path, PathBuf};
use std::ptr;

#[allow(deprecated)]
use llvm_sys::bit_reader::LLVMParseBitcodeInContext;
use llvm_sys::core::*;
use llvm_sys::debuginfo::*;
use llvm_sys::ir_reader::LLVMParseIRInContext;
use llvm_sys::prelude::*;
use llvm_sys::target::{
    LLVMABIAlignmentOfType, LLVMABISizeOfType, LLVMGetModuleDataLayout, LLVMOffsetOfElement,
    LLVMPointerSize, LLVMTargetDataRef,
};
use llvm_sys::{
    LLVMAtomicOrdering, LLVMDLLStorageClass, LLVMLinkage, LLVMOpcode, LLVMTypeKind, LLVMVisibility,
};

use crate::{
    AbiClass, Access, Func, Global, Loc, LoweringStats, Param, Pir, PirError, ScalarTypeClass,
    Signature, StatementBoundary, StatementCfg, Stmt, SymbolLinkage, TargetInfo,
};

type AliasMap = BTreeMap<String, AliasTarget>;

const MAX_CONSTANT_EXPR_LOWER_DEPTH: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
enum AliasTarget {
    Function(String),
    Global(String),
}

pub fn lower_path(path: &Path, repo_root: Option<&Path>) -> Result<Pir, PirError> {
    let roots = repo_root.map(RepoRoots::new).transpose()?;
    let module = ParsedModule::from_path(path)?;
    Ok(unsafe { lower_module(module.module, roots.as_ref()) })
}

struct RepoRoots {
    resolved: PathBuf,
    given_absolute: PathBuf,
}

impl RepoRoots {
    fn new(path: &Path) -> Result<Self, PirError> {
        let given_absolute = if path.is_absolute() {
            path.to_owned()
        } else {
            std::env::current_dir()
                .map_err(|source| PirError::Read {
                    path: path.display().to_string(),
                    source,
                })?
                .join(path)
        };
        let resolved = std::fs::canonicalize(&given_absolute).map_err(|source| PirError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Ok(Self {
            resolved: lexical_normalize(&resolved),
            given_absolute: lexical_normalize(&given_absolute),
        })
    }

    fn relative_source(&self, source: &Path) -> Option<String> {
        if !source.is_absolute() {
            return None;
        }
        let source = lexical_normalize(source);
        source
            .strip_prefix(&self.resolved)
            .or_else(|_| source.strip_prefix(&self.given_absolute))
            .ok()
            .filter(|relative| !relative.as_os_str().is_empty())
            .map(|relative| relative.to_string_lossy().replace('\\', "/"))
            .filter(|relative| !relative.contains("::"))
    }
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
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
    aliases: AliasMap,
    ifunc_names: BTreeSet<String>,
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
            let width = LLVMGetIntTypeWidth(LLVMTypeOf(value));
            if width <= 64 {
                return LLVMConstIntGetSExtValue(value).to_string();
            }
            // LLVMConstIntGetSExtValue aborts for values whose significant bits do not
            // fit in i64. Wide integers cannot be D3 atomics on current targets, but
            // scalar lowering must still retain them without crashing.
            return value_string(value);
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

unsafe fn lower_module(module: LLVMModuleRef, repo_roots: Option<&RepoRoots>) -> Pir {
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

    let alias_map = collect_alias_map(&aliases, &func_names, &global_names, &mut lowering);
    let ifunc_names = ifuncs
        .iter()
        .map(|ifunc| value_name(*ifunc))
        .collect::<BTreeSet<_>>();
    for ifunc in &ifuncs {
        lowering.bump_tainted(format!("ifunc:{}", value_name(*ifunc)));
    }

    let ctx = ModuleCtx {
        data_layout: LLVMGetModuleDataLayout(module),
        func_names,
        global_names,
        aliases: alias_map,
        ifunc_names,
    };

    let address_taken = collect_address_taken(&ctx, &globals, &aliases, &functions);

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
                repo_roots,
            ));
        }
    }

    let pir_globals = globals
        .iter()
        .map(|global| {
            let ty = LLVMGlobalGetValueType(*global);
            let debug = global_debug_info(module, *global, repo_roots);
            if debug.is_none() {
                lowering.bump_missing_debug_location("global");
            }
            Global {
                key: value_name(*global),
                file: debug.as_ref().and_then(|debug| debug.file.clone()),
                line: debug.as_ref().and_then(|debug| debug.line),
                is_const: LLVMIsGlobalConstant(*global) != 0,
                mutable: LLVMIsGlobalConstant(*global) == 0,
                exported: is_exported(
                    LLVMGetLinkage(*global),
                    LLVMGetVisibility(*global),
                    LLVMGetDLLStorageClass(*global),
                ),
                is_definition: LLVMIsDeclaration(*global) == 0,
                linkage: symbol_linkage(LLVMGetLinkage(*global)),
                type_spelling: debug.as_ref().and_then(|debug| debug.type_spelling.clone()),
                size_bits: Some(LLVMABISizeOfType(ctx.data_layout, ty).saturating_mul(8)),
                align_bits: Some(
                    u64::from(LLVMABIAlignmentOfType(ctx.data_layout, ty)).saturating_mul(8),
                ),
                path_error: debug.as_ref().and_then(|debug| debug.path_error.clone()),
                scalar_class: debug.as_ref().and_then(|debug| debug.scalar_class),
                signed: debug.as_ref().and_then(|debug| debug.signed),
                initializer_ir: {
                    let initializer = LLVMGetInitializer(*global);
                    (!initializer.is_null()).then(|| value_string(initializer))
                },
                init_refs: collect_global_init_refs(*global),
            }
        })
        .collect::<Vec<_>>();
    let global_init = lower_global_initializers(&ctx, &globals, &mut lowering);

    Pir {
        module: module_identifier(module),
        source: Some(module_source_file(module)),
        lowering,
        target: Some(module_target_info(module, ctx.data_layout)),
        functions: pir_functions,
        globals: pir_globals,
        global_init,
    }
}

unsafe fn module_target_info(module: LLVMModuleRef, data_layout: LLVMTargetDataRef) -> TargetInfo {
    let pointer_bits = u64::from(LLVMPointerSize(data_layout)).saturating_mul(8);
    let mut supported_atomic_widths = vec![8, 16, 32];
    if pointer_bits >= 64 {
        supported_atomic_widths.push(64);
    }
    TargetInfo {
        triple: c_string_or_empty(LLVMGetTarget(module)),
        data_layout: c_string_or_empty(LLVMGetDataLayoutStr(module)),
        supported_atomic_widths,
    }
}

unsafe fn c_string_or_empty(value: *const c_char) -> String {
    if value.is_null() {
        String::new()
    } else {
        CStr::from_ptr(value).to_string_lossy().into_owned()
    }
}

fn symbol_linkage(linkage: LLVMLinkage) -> SymbolLinkage {
    match linkage {
        LLVMLinkage::LLVMInternalLinkage | LLVMLinkage::LLVMPrivateLinkage => {
            SymbolLinkage::Internal
        }
        _ => SymbolLinkage::External,
    }
}

struct GlobalDebugInfo {
    file: Option<String>,
    line: Option<u32>,
    type_spelling: Option<String>,
    path_error: Option<String>,
    scalar_class: Option<ScalarTypeClass>,
    signed: Option<bool>,
}

unsafe fn global_debug_info(
    module: LLVMModuleRef,
    global: LLVMValueRef,
    repo_roots: Option<&RepoRoots>,
) -> Option<GlobalDebugInfo> {
    let mut count = 0usize;
    let entries = LLVMGlobalCopyAllMetadata(global, &mut count);
    if entries.is_null() {
        return None;
    }
    let context = LLVMGetModuleContext(module);
    let mut result = None;
    for index in 0..count {
        let metadata = LLVMValueMetadataEntriesGetMetadata(entries, index as u32);
        if metadata.is_null()
            || !matches!(
                LLVMGetMetadataKind(metadata),
                LLVMMetadataKind::LLVMDIGlobalVariableExpressionMetadataKind
            )
        {
            continue;
        }
        let variable = LLVMDIGlobalVariableExpressionGetVariable(metadata);
        if variable.is_null() {
            continue;
        }
        let file = LLVMDIVariableGetFile(variable);
        let Some(raw_file) = di_file_path(file) else {
            continue;
        };
        let file = match repo_roots {
            None => Some(raw_file.clone()),
            Some(roots) => roots.relative_source(Path::new(&raw_file)),
        };
        let path_error = (file.is_none() && repo_roots.is_some()).then(|| raw_file.clone());
        let line = LLVMDIVariableGetLine(variable);
        let (type_spelling, scalar_class, signed) = metadata_operand(context, variable, 3)
            .map(|ty| di_type_details(context, ty))
            .unwrap_or((None, None, None));
        result = Some(GlobalDebugInfo {
            file,
            line: (line != 0).then_some(line),
            type_spelling,
            path_error,
            scalar_class,
            signed,
        });
        break;
    }
    LLVMDisposeValueMetadataEntries(entries);
    result
}

unsafe fn metadata_operand(
    context: LLVMContextRef,
    metadata: LLVMMetadataRef,
    index: usize,
) -> Option<LLVMMetadataRef> {
    let value = LLVMMetadataAsValue(context, metadata);
    let count = LLVMGetMDNodeNumOperands(value) as usize;
    if index >= count {
        return None;
    }
    let mut operands = vec![ptr::null_mut(); count];
    LLVMGetMDNodeOperands(value, operands.as_mut_ptr());
    let operand = operands[index];
    if operand.is_null() {
        None
    } else {
        Some(LLVMValueAsMetadata(operand))
    }
}

unsafe fn di_type_name(metadata: LLVMMetadataRef) -> Option<String> {
    match LLVMGetMetadataKind(metadata) {
        LLVMMetadataKind::LLVMDIBasicTypeMetadataKind
        | LLVMMetadataKind::LLVMDIDerivedTypeMetadataKind
        | LLVMMetadataKind::LLVMDICompositeTypeMetadataKind => {}
        _ => return None,
    }
    let mut len = 0usize;
    let ptr = LLVMDITypeGetName(metadata, &mut len);
    (!ptr.is_null() && len != 0).then(|| {
        String::from_utf8_lossy(std::slice::from_raw_parts(ptr.cast::<u8>(), len)).into_owned()
    })
}

unsafe fn di_type_details(
    context: LLVMContextRef,
    metadata: LLVMMetadataRef,
) -> (Option<String>, Option<ScalarTypeClass>, Option<bool>) {
    let name = di_type_name(metadata);
    let (class, signed) = di_type_class(context, metadata, 0);
    (name, class, signed)
}

unsafe fn di_type_class(
    context: LLVMContextRef,
    metadata: LLVMMetadataRef,
    depth: usize,
) -> (Option<ScalarTypeClass>, Option<bool>) {
    if depth >= 32 {
        return (None, None);
    }
    let printed = value_string(LLVMMetadataAsValue(context, metadata));
    match LLVMGetMetadataKind(metadata) {
        LLVMMetadataKind::LLVMDIBasicTypeMetadataKind if printed.contains("DW_ATE_boolean") => {
            (Some(ScalarTypeClass::Boolean), None)
        }
        LLVMMetadataKind::LLVMDIBasicTypeMetadataKind if printed.contains("DW_ATE_unsigned") => {
            (Some(ScalarTypeClass::Integer), Some(false))
        }
        LLVMMetadataKind::LLVMDIBasicTypeMetadataKind if printed.contains("DW_ATE_signed") => {
            (Some(ScalarTypeClass::Integer), Some(true))
        }
        LLVMMetadataKind::LLVMDICompositeTypeMetadataKind
            if printed.contains("DW_TAG_enumeration_type") =>
        {
            let signed = metadata_operand(context, metadata, 3)
                .and_then(|base| di_type_class(context, base, depth + 1).1);
            (Some(ScalarTypeClass::Enum), signed)
        }
        LLVMMetadataKind::LLVMDIDerivedTypeMetadataKind
            if printed.contains("DW_TAG_pointer_type") =>
        {
            (Some(ScalarTypeClass::Pointer), None)
        }
        LLVMMetadataKind::LLVMDIDerivedTypeMetadataKind => metadata_operand(context, metadata, 3)
            .map(|base| di_type_class(context, base, depth + 1))
            .unwrap_or((None, None)),
        _ => (None, None),
    }
}

unsafe fn di_file_path(file: LLVMMetadataRef) -> Option<String> {
    if file.is_null()
        || !matches!(
            LLVMGetMetadataKind(file),
            LLVMMetadataKind::LLVMDIFileMetadataKind
        )
    {
        return None;
    }
    let mut filename_len = 0u32;
    let filename = LLVMDIFileGetFilename(file, &mut filename_len);
    if filename.is_null() || filename_len == 0 {
        return None;
    }
    let filename = String::from_utf8_lossy(std::slice::from_raw_parts(
        filename.cast::<u8>(),
        filename_len as usize,
    ));
    if Path::new(filename.as_ref()).is_absolute() {
        return Some(filename.into_owned());
    }
    let mut directory_len = 0u32;
    let directory = LLVMDIFileGetDirectory(file, &mut directory_len);
    if directory.is_null() || directory_len == 0 {
        return Some(filename.into_owned());
    }
    let directory = String::from_utf8_lossy(std::slice::from_raw_parts(
        directory.cast::<u8>(),
        directory_len as usize,
    ));
    Some(
        Path::new(directory.as_ref())
            .join(filename.as_ref())
            .to_string_lossy()
            .into_owned(),
    )
}

unsafe fn lower_function(
    ctx: &ModuleCtx,
    function: LLVMValueRef,
    address_taken: &BTreeSet<String>,
    lowering: &mut LoweringStats,
    repo_roots: Option<&RepoRoots>,
) -> Func {
    let debug = function_debug_info(function, repo_roots);
    let has_function_debug = debug.is_some();
    if debug.is_none() {
        lowering.bump_missing_debug_location("function");
    }
    let key = value_name(function);
    let mut body = Vec::new();
    let mut fctx = FunctionCtx::new(key.clone());
    let param_names = function_param_names(function, &mut fctx);
    lower_personality_function(ctx, function, lowering);

    let mut blocks = Vec::new();
    let mut block = LLVMGetFirstBasicBlock(function);
    while !block.is_null() {
        blocks.push(block);
        block = LLVMGetNextBasicBlock(block);
    }

    let mut raw_boundaries = Vec::with_capacity(blocks.len());
    for &block in &blocks {
        let mut groups = Vec::<RawStatementBoundary>::new();
        let mut inst = LLVMGetFirstInstruction(block);
        while !inst.is_null() {
            let opcode = LLVMGetInstructionOpcode(inst);
            let key = opcode_key_for_inst(inst, opcode);
            if LLVMIsATerminatorInst(inst).is_null() {
                lowering.bump_instruction(key);
            } else {
                lowering.bump_terminator(key);
            }
            let statement_loc = normalized_statement_loc(inst, repo_roots);
            let first_stmt = body.len();
            lower_instruction(ctx, &mut fctx, inst, opcode, &mut body, lowering);
            let stmt_indices = (first_stmt..body.len()).map(|index| index as u32);
            if let Some(group) = groups.last_mut().filter(|group| group.loc == statement_loc) {
                group.stmt_indices.extend(stmt_indices);
            } else {
                groups.push(RawStatementBoundary {
                    loc: statement_loc,
                    stmt_indices: stmt_indices.collect(),
                });
            }
            inst = LLVMGetNextInstruction(inst);
        }
        if groups.is_empty() {
            groups.push(RawStatementBoundary::default());
        }
        raw_boundaries.push(groups);
    }

    let statement_cfg = build_statement_cfg(&blocks, raw_boundaries, has_function_debug);
    lowering.statement_cfgs.insert(key.clone(), statement_cfg);

    Func {
        key: key.clone(),
        sig: function_signature(ctx, function, lowering),
        param_names,
        file: debug.as_ref().and_then(|debug| debug.0.clone()),
        line: debug.and_then(|debug| debug.1),
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

#[derive(Default)]
struct RawStatementBoundary {
    loc: Option<Loc>,
    stmt_indices: Vec<u32>,
}

unsafe fn normalized_statement_loc(
    instruction: LLVMValueRef,
    repo_roots: Option<&RepoRoots>,
) -> Option<Loc> {
    let mut location = loc(instruction)?;
    if let Some(roots) = repo_roots {
        if let Some(relative) = roots.relative_source(Path::new(&location.file)) {
            location.file = relative;
        }
    }
    Some(location)
}

unsafe fn build_statement_cfg(
    blocks: &[LLVMBasicBlockRef],
    raw_blocks: Vec<Vec<RawStatementBoundary>>,
    has_function_debug: bool,
) -> StatementCfg {
    let mut first_boundary = Vec::with_capacity(raw_blocks.len());
    let mut next_id = 0_u32;
    for groups in &raw_blocks {
        first_boundary.push(next_id);
        next_id += groups.len() as u32;
    }

    let mut boundaries = Vec::with_capacity(next_id as usize);
    for (block_index, groups) in raw_blocks.into_iter().enumerate() {
        let group_count = groups.len();
        for (ordinal, group) in groups.into_iter().enumerate() {
            let id = first_boundary[block_index] + ordinal as u32;
            let mut successors = if ordinal + 1 < group_count {
                vec![id + 1]
            } else {
                llvm_block_successors(blocks, block_index, &first_boundary)
            };
            successors.sort_unstable();
            successors.dedup();
            boundaries.push(StatementBoundary {
                id,
                block: block_index as u32,
                ordinal: ordinal as u32,
                insertable: group.loc.is_some(),
                loc: group.loc,
                stmt_indices: group.stmt_indices,
                successors,
                predecessors: Vec::new(),
            });
        }
    }

    let edges = boundaries
        .iter()
        .flat_map(|boundary| {
            boundary
                .successors
                .iter()
                .map(move |successor| (boundary.id, *successor))
        })
        .collect::<Vec<_>>();
    for (predecessor, successor) in edges {
        if let Some(boundary) = boundaries.get_mut(successor as usize) {
            boundary.predecessors.push(predecessor);
        }
    }
    for boundary in &mut boundaries {
        boundary.predecessors.sort_unstable();
        boundary.predecessors.dedup();
    }

    // More than one statement group on a source line is not a unique source insertion point.
    let mut by_line = BTreeMap::<(String, u32), Vec<usize>>::new();
    for (index, boundary) in boundaries.iter().enumerate() {
        if let Some(location) = &boundary.loc {
            by_line
                .entry((location.file.clone(), location.line))
                .or_default()
                .push(index);
        }
    }
    for indices in by_line.values().filter(|indices| indices.len() > 1) {
        for &index in indices {
            boundaries[index].insertable = false;
        }
    }

    // Debug locations that move backwards inside one LLVM block cannot identify a stable source
    // statement boundary. Keep the CFG node for dataflow, but refuse it as a publication site.
    for block_index in 0..blocks.len() as u32 {
        let mut previous: Option<(String, u32, u32)> = None;
        for boundary in boundaries
            .iter_mut()
            .filter(|boundary| boundary.block == block_index)
        {
            let Some(location) = &boundary.loc else {
                continue;
            };
            let current = (location.file.clone(), location.line, location.col);
            if previous
                .as_ref()
                .is_some_and(|previous| current <= *previous)
            {
                boundary.insertable = false;
            }
            previous = Some(current);
        }
    }

    StatementCfg {
        entry: first_boundary.first().copied().unwrap_or(0),
        source_mapping_available: has_function_debug
            && boundaries.iter().any(|boundary| boundary.insertable),
        boundaries,
    }
}

unsafe fn llvm_block_successors(
    blocks: &[LLVMBasicBlockRef],
    block_index: usize,
    first_boundary: &[u32],
) -> Vec<u32> {
    let terminator = LLVMGetBasicBlockTerminator(blocks[block_index]);
    if terminator.is_null() {
        return Vec::new();
    }
    (0..LLVMGetNumSuccessors(terminator))
        .filter_map(|index| {
            let successor = LLVMGetSuccessor(terminator, index);
            blocks
                .iter()
                .position(|candidate| *candidate == successor)
                .map(|successor_index| first_boundary[successor_index])
        })
        .collect()
}

unsafe fn function_debug_info(
    function: LLVMValueRef,
    repo_roots: Option<&RepoRoots>,
) -> Option<(Option<String>, Option<u32>)> {
    let subprogram = LLVMGetSubprogram(function);
    if subprogram.is_null() {
        return None;
    }
    let raw_file = di_file_path(LLVMDIScopeGetFile(subprogram))?;
    let file = match repo_roots {
        None => Some(raw_file),
        Some(roots) => roots.relative_source(Path::new(&raw_file)),
    };
    let line = LLVMDISubprogramGetLine(subprogram);
    Some((file, (line != 0).then_some(line)))
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
        param_names: Vec::new(),
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

unsafe fn function_param_names(function: LLVMValueRef, fctx: &mut FunctionCtx) -> Vec<String> {
    let count = LLVMCountParams(function);
    let mut out = Vec::with_capacity(count as usize);
    for index in 0..count {
        out.push(fctx.local_key(LLVMGetParam(function, index)));
    }
    out
}

/// Proves that a `ptrtoint` result remains inside the small integer domain whose only terminal
/// operation is `icmp`. Unknown users fail closed. Cyclic phi graphs are accepted only when every
/// edge leaving the cycle eventually reaches a supported comparison/arithmetic node.
unsafe fn ptrtoint_has_closed_comparison_uses(value: LLVMValueRef) -> bool {
    unsafe fn visit(
        value: LLVMValueRef,
        visiting: &mut BTreeSet<usize>,
        memo: &mut BTreeMap<usize, bool>,
    ) -> bool {
        let key = value as usize;
        if let Some(&closed) = memo.get(&key) {
            return closed;
        }
        if !visiting.insert(key) {
            return true;
        }

        let mut current_use = LLVMGetFirstUse(value);
        let mut closed = true;
        while !current_use.is_null() {
            let user = LLVMGetUser(current_use);
            if user.is_null() || LLVMIsAInstruction(user).is_null() {
                closed = false;
                break;
            }
            closed = match LLVMGetInstructionOpcode(user) {
                LLVMOpcode::LLVMICmp => true,
                LLVMOpcode::LLVMAdd
                | LLVMOpcode::LLVMSub
                | LLVMOpcode::LLVMAnd
                | LLVMOpcode::LLVMOr
                | LLVMOpcode::LLVMXor
                | LLVMOpcode::LLVMPHI
                | LLVMOpcode::LLVMSelect => visit(user, visiting, memo),
                _ => false,
            };
            if !closed {
                break;
            }
            current_use = LLVMGetNextUse(current_use);
        }

        visiting.remove(&key);
        memo.insert(key, closed);
        closed
    }

    visit(value, &mut BTreeSet::new(), &mut BTreeMap::new())
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
            if LLVMGetVolatile(inst) != 0 {
                lowering.bump_modeled("volatile_load");
            }
            if is_atomic_memory_inst(inst) {
                lowering.bump_modeled("atomic_load");
            }
            bump_missing_loc(lowering, "load", inst);
            if let Some(global) = operand_global_name(ctx, address) {
                body.push(Stmt::GlobalRef {
                    global,
                    access: Access::Ref,
                    volatile: LLVMGetVolatile(inst) != 0,
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
            if LLVMGetVolatile(inst) != 0 {
                lowering.bump_modeled("volatile_store");
            }
            if is_atomic_memory_inst(inst) {
                lowering.bump_modeled("atomic_store");
            }
            bump_missing_loc(lowering, "store", inst);
            if let Some(global) = operand_global_name(ctx, address) {
                body.push(Stmt::GlobalRef {
                    global,
                    access: Access::Mod,
                    volatile: LLVMGetVolatile(inst) != 0,
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
        LLVMOpcode::LLVMAdd
        | LLVMOpcode::LLVMSub
        | LLVMOpcode::LLVMAnd
        | LLVMOpcode::LLVMOr
        | LLVMOpcode::LLVMXor => {
            let op = match opcode {
                LLVMOpcode::LLVMAdd => crate::ScalarOp::Add,
                LLVMOpcode::LLVMSub => crate::ScalarOp::Sub,
                LLVMOpcode::LLVMAnd => crate::ScalarOp::And,
                LLVMOpcode::LLVMOr => crate::ScalarOp::Or,
                LLVMOpcode::LLVMXor => crate::ScalarOp::Xor,
                _ => unreachable!(),
            };
            body.push(Stmt::ScalarOp {
                dest: fctx.local_key(inst),
                op,
                lhs: fctx.operand_key(LLVMGetOperand(inst, 0)),
                rhs: fctx.operand_key(LLVMGetOperand(inst, 1)),
                loc: loc(inst),
            });
            lowering.bump_modeled(format!("scalar_{}", opcode_key(opcode)));
            bump_missing_loc(lowering, opcode_key(opcode), inst);
        }
        LLVMOpcode::LLVMPtrToInt => {
            let source = LLVMGetOperand(inst, 0);
            body.push(Stmt::PtrToInt {
                dest: fctx.local_key(inst),
                source: fctx.operand_key(source),
                comparison_only: ptrtoint_has_closed_comparison_uses(inst),
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
        LLVMOpcode::LLVMInvoke => lower_invoke(ctx, fctx, inst, body, lowering),
        LLVMOpcode::LLVMCallBr => lower_callbr(ctx, fctx, inst, body, lowering),
        LLVMOpcode::LLVMPHI => lower_phi(fctx, inst, body, lowering),
        LLVMOpcode::LLVMSelect => lower_select(fctx, inst, body, lowering),
        LLVMOpcode::LLVMFreeze => lower_freeze(fctx, inst, body, lowering),
        LLVMOpcode::LLVMExtractElement => lower_extract_element(fctx, inst, body, lowering),
        LLVMOpcode::LLVMInsertElement => lower_insert_element(inst, fctx, body, lowering),
        LLVMOpcode::LLVMShuffleVector => lower_shuffle_vector(fctx, inst, body, lowering),
        LLVMOpcode::LLVMExtractValue => lower_extract_value(fctx, inst, body, lowering),
        LLVMOpcode::LLVMInsertValue => lower_insert_value(inst, fctx, body, lowering),
        LLVMOpcode::LLVMLandingPad => lower_landingpad(inst, fctx, body, lowering),
        LLVMOpcode::LLVMAtomicCmpXchg => lower_cmpxchg(ctx, fctx, inst, body, lowering),
        LLVMOpcode::LLVMAtomicRMW => lower_atomicrmw(ctx, fctx, inst, body, lowering),
        LLVMOpcode::LLVMVAArg => lower_va_arg(fctx, inst, body, lowering),
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
        _ => {
            if LLVMIsATerminatorInst(inst).is_null() {
                lowering.bump_skipped(format!("unmodeled_instruction:{}", opcode_key(opcode)));
            }
        }
    }
}

unsafe fn lower_call(
    ctx: &ModuleCtx,
    fctx: &mut FunctionCtx,
    inst: LLVMValueRef,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    lower_call_site(ctx, fctx, inst, "call", "inline_asm", body, lowering);
}

unsafe fn lower_invoke(
    ctx: &ModuleCtx,
    fctx: &mut FunctionCtx,
    inst: LLVMValueRef,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    lowering.bump_tainted("invoke_exception_control_flow");
    lower_call_site(ctx, fctx, inst, "invoke", "inline_asm", body, lowering);
}

unsafe fn lower_callbr(
    ctx: &ModuleCtx,
    fctx: &mut FunctionCtx,
    inst: LLVMValueRef,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    lowering.bump_tainted("callbr");
    lower_call_site(
        ctx,
        fctx,
        inst,
        "callbr",
        "inline_asm_callbr",
        body,
        lowering,
    );
}

unsafe fn lower_call_site(
    ctx: &ModuleCtx,
    fctx: &mut FunctionCtx,
    inst: LLVMValueRef,
    op: &str,
    inline_reason: &str,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    let called = LLVMGetCalledValue(inst);
    if !LLVMIsAInlineAsm(called).is_null() {
        if inline_reason == "inline_asm" {
            lowering.bump_tainted("inline_asm");
        }
        push_unknown(
            body,
            op,
            call_operand_keys(fctx, inst),
            call_result_keys(fctx, inst),
            inline_reason,
            loc(inst),
            lowering,
        );
        bump_missing_loc(lowering, op, inst);
        return;
    }

    if let Some(callee) = direct_symbol_name(called) {
        if callee.starts_with("llvm.dbg.") {
            lowering.bump_skipped("dbg_intrinsic");
            return;
        }
        if lower_intrinsic_call(ctx, fctx, &callee, inst, body, lowering) {
            return;
        }
        if ctx.ifunc_names.contains(&callee) {
            lower_ifunc_call(fctx, op, &callee, inst, body, lowering);
            bump_missing_loc(lowering, op, inst);
            return;
        }
    }

    let sig = call_signature(ctx, inst, lowering);
    let args = call_operand_keys(fctx, inst);
    let dest = call_result_key(fctx, inst);
    match direct_symbol_name(called) {
        Some(callee) if is_skipped_intrinsic(&callee) => {}
        Some(callee) if resolve_function_name(ctx, &callee).is_some() => {
            let resolved = resolve_function_name(ctx, &callee).unwrap();
            if resolved != callee {
                lowering.bump_modeled("alias_call_direct");
            }
            body.push(Stmt::CallDirect {
                callee: resolved,
                sig,
                args,
                dest,
                loc: loc(inst),
            });
            lowering.bump_modeled("call_direct");
        }
        _ => {
            body.push(Stmt::CallIndirect {
                operand: fctx.operand_key(called),
                sig,
                args,
                dest,
                loc: loc(inst),
            });
            lowering.bump_modeled("call_indirect");
        }
    }
    bump_missing_loc(lowering, op, inst);
}

unsafe fn lower_ifunc_call(
    fctx: &mut FunctionCtx,
    op: &str,
    callee: &str,
    inst: LLVMValueRef,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    lowering.bump_tainted(format!("ifunc_callee:{callee}"));
    push_unknown(
        body,
        op,
        call_operand_keys(fctx, inst),
        call_result_keys(fctx, inst),
        "ifunc_callee",
        loc(inst),
        lowering,
    );
}

unsafe fn lower_phi(
    fctx: &mut FunctionCtx,
    inst: LLVMValueRef,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    if is_pointer_like_type(LLVMTypeOf(inst)) {
        let incoming = LLVMCountIncoming(inst);
        body.push(Stmt::Assign {
            dest: fctx.local_key(inst),
            sources: (0..incoming)
                .map(|index| fctx.operand_key(LLVMGetIncomingValue(inst, index)))
                .collect(),
            loc: loc(inst),
        });
        lowering.bump_modeled("assign");
    } else if (0..LLVMCountIncoming(inst))
        .any(|index| is_pointer_like_type(LLVMTypeOf(LLVMGetIncomingValue(inst, index))))
    {
        lowering.bump_tainted("phi_pointer_operand_non_pointer_result");
    } else {
        lowering.bump_skipped("phi_non_pointer");
    }
    bump_missing_loc(lowering, "phi", inst);
}

unsafe fn lower_select(
    fctx: &mut FunctionCtx,
    inst: LLVMValueRef,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    let true_value = LLVMGetOperand(inst, 1);
    let false_value = LLVMGetOperand(inst, 2);
    if is_pointer_like_type(LLVMTypeOf(true_value)) || is_pointer_like_type(LLVMTypeOf(false_value))
    {
        body.push(Stmt::Assign {
            dest: fctx.local_key(inst),
            sources: vec![fctx.operand_key(true_value), fctx.operand_key(false_value)],
            loc: loc(inst),
        });
        lowering.bump_modeled("assign");
    } else {
        lowering.bump_skipped("select_non_pointer");
    }
    bump_missing_loc(lowering, "select", inst);
}

unsafe fn lower_freeze(
    fctx: &mut FunctionCtx,
    inst: LLVMValueRef,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    body.push(Stmt::Assign {
        dest: fctx.local_key(inst),
        sources: vec![fctx.operand_key(LLVMGetOperand(inst, 0))],
        loc: loc(inst),
    });
    lowering.bump_modeled("assign");
    bump_missing_loc(lowering, "freeze", inst);
}

unsafe fn lower_extract_element(
    fctx: &mut FunctionCtx,
    inst: LLVMValueRef,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    if is_pointer_vector_type(LLVMTypeOf(LLVMGetOperand(inst, 0))) {
        lowering.bump_tainted("pointer_vector:extractelement");
        push_unknown(
            body,
            "extractelement",
            vec![
                fctx.operand_key(LLVMGetOperand(inst, 0)),
                fctx.operand_key(LLVMGetOperand(inst, 1)),
            ],
            vec![fctx.local_key(inst)],
            "pointer_vector",
            loc(inst),
            lowering,
        );
    } else {
        lowering.bump_skipped("extractelement_non_pointer_vector");
    }
    bump_missing_loc(lowering, "extractelement", inst);
}

unsafe fn lower_insert_element(
    inst: LLVMValueRef,
    fctx: &mut FunctionCtx,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    if is_pointer_vector_type(LLVMTypeOf(LLVMGetOperand(inst, 0)))
        || is_pointer_like_type(LLVMTypeOf(LLVMGetOperand(inst, 1)))
    {
        lowering.bump_tainted("pointer_vector:insertelement");
        push_unknown(
            body,
            "insertelement",
            vec![
                fctx.operand_key(LLVMGetOperand(inst, 0)),
                fctx.operand_key(LLVMGetOperand(inst, 1)),
                fctx.operand_key(LLVMGetOperand(inst, 2)),
            ],
            vec![fctx.local_key(inst)],
            "pointer_vector",
            loc(inst),
            lowering,
        );
    } else {
        lowering.bump_skipped("insertelement_non_pointer_vector");
    }
    bump_missing_loc(lowering, "insertelement", inst);
}

unsafe fn lower_shuffle_vector(
    fctx: &mut FunctionCtx,
    inst: LLVMValueRef,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    if is_pointer_vector_type(LLVMTypeOf(LLVMGetOperand(inst, 0)))
        || is_pointer_vector_type(LLVMTypeOf(LLVMGetOperand(inst, 1)))
        || is_pointer_vector_type(LLVMTypeOf(inst))
    {
        lowering.bump_tainted("pointer_vector:shufflevector");
        push_unknown(
            body,
            "shufflevector",
            vec![
                fctx.operand_key(LLVMGetOperand(inst, 0)),
                fctx.operand_key(LLVMGetOperand(inst, 1)),
                value_string(LLVMGetOperand(inst, 2)),
            ],
            vec![fctx.local_key(inst)],
            "pointer_vector",
            loc(inst),
            lowering,
        );
    } else {
        lowering.bump_skipped("shufflevector_non_pointer_vector");
    }
    bump_missing_loc(lowering, "shufflevector", inst);
}

unsafe fn lower_extract_value(
    fctx: &mut FunctionCtx,
    inst: LLVMValueRef,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    let result_type = LLVMTypeOf(inst);
    if is_pointer_vector_type(result_type) {
        lowering.bump_tainted("pointer_vector:extractvalue");
        push_unknown(
            body,
            "extractvalue",
            vec![fctx.operand_key(LLVMGetOperand(inst, 0))],
            vec![fctx.local_key(inst)],
            "pointer_vector",
            loc(inst),
            lowering,
        );
    } else if is_pointer_like_type(result_type) {
        body.push(Stmt::Assign {
            dest: fctx.local_key(inst),
            sources: vec![fctx.operand_key(LLVMGetOperand(inst, 0))],
            loc: loc(inst),
        });
        lowering.bump_modeled("extractvalue");
        lowering.bump_modeled("assign");
    } else if type_contains_pointer(LLVMTypeOf(LLVMGetOperand(inst, 0))) {
        lowering.bump_tainted("extractvalue_pointer_aggregate_non_pointer_result");
    } else {
        lowering.bump_skipped("extractvalue_non_pointer");
    }
    bump_missing_loc(lowering, "extractvalue", inst);
}

unsafe fn lower_insert_value(
    inst: LLVMValueRef,
    fctx: &mut FunctionCtx,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    if type_contains_pointer(LLVMTypeOf(inst))
        || type_contains_pointer(LLVMTypeOf(LLVMGetOperand(inst, 1)))
    {
        body.push(Stmt::Assign {
            dest: fctx.local_key(inst),
            sources: vec![
                fctx.operand_key(LLVMGetOperand(inst, 0)),
                fctx.operand_key(LLVMGetOperand(inst, 1)),
            ],
            loc: loc(inst),
        });
        lowering.bump_modeled("insertvalue");
        lowering.bump_modeled("assign");
        lowering.bump_tainted("insertvalue_coarse");
    } else {
        lowering.bump_skipped("insertvalue_non_pointer");
    }
    bump_missing_loc(lowering, "insertvalue", inst);
}

unsafe fn lower_landingpad(
    inst: LLVMValueRef,
    fctx: &mut FunctionCtx,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    if type_contains_pointer(LLVMTypeOf(inst)) {
        lowering.bump_tainted("landingpad_pointer_result");
        push_unknown(
            body,
            "landingpad",
            Vec::new(),
            vec![fctx.local_key(inst)],
            "landingpad_pointer_result",
            loc(inst),
            lowering,
        );
    } else {
        lowering.bump_skipped("landingpad_non_pointer");
    }
    bump_missing_loc(lowering, "landingpad", inst);
}

unsafe fn lower_cmpxchg(
    _ctx: &ModuleCtx,
    fctx: &mut FunctionCtx,
    inst: LLVMValueRef,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    let address = LLVMGetOperand(inst, 0);
    let replacement = LLVMGetOperand(inst, 2);
    body.push(Stmt::Load {
        dest: format!("{}.old", fctx.local_key(inst)),
        address: fctx.operand_key(address),
        loc: loc(inst),
    });
    body.push(Stmt::Store {
        address: fctx.operand_key(address),
        value: fctx.operand_key(replacement),
        loc: loc(inst),
    });
    lowering.bump_modeled("cmpxchg");
    lowering.bump_modeled("atomic_load");
    lowering.bump_modeled("atomic_store");
    if LLVMGetVolatile(inst) != 0 {
        lowering.bump_modeled("volatile_cmpxchg");
    }
    bump_missing_loc(lowering, "cmpxchg", inst);
}

unsafe fn lower_atomicrmw(
    _ctx: &ModuleCtx,
    fctx: &mut FunctionCtx,
    inst: LLVMValueRef,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    let address = LLVMGetOperand(inst, 0);
    let value = LLVMGetOperand(inst, 1);
    body.push(Stmt::Load {
        dest: fctx.local_key(inst),
        address: fctx.operand_key(address),
        loc: loc(inst),
    });
    body.push(Stmt::Store {
        address: fctx.operand_key(address),
        value: fctx.operand_key(value),
        loc: loc(inst),
    });
    lowering.bump_modeled("atomicrmw");
    lowering.bump_modeled("atomic_load");
    lowering.bump_modeled("atomic_store");
    if LLVMGetVolatile(inst) != 0 {
        lowering.bump_modeled("volatile_atomicrmw");
    }
    bump_missing_loc(lowering, "atomicrmw", inst);
}

unsafe fn lower_va_arg(
    fctx: &mut FunctionCtx,
    inst: LLVMValueRef,
    body: &mut Vec<Stmt>,
    lowering: &mut LoweringStats,
) {
    lowering.bump_tainted("va_arg");
    push_unknown(
        body,
        "va_arg",
        vec![fctx.operand_key(LLVMGetOperand(inst, 0))],
        vec![fctx.local_key(inst)],
        "va_arg",
        loc(inst),
        lowering,
    );
    bump_missing_loc(lowering, "va_arg", inst);
}

unsafe fn lower_intrinsic_call(
    _ctx: &ModuleCtx,
    fctx: &mut FunctionCtx,
    callee: &str,
    inst: LLVMValueRef,
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
        if LLVMGetNumArgOperands(inst) >= 3 {
            body.push(Stmt::Memcpy {
                dst: fctx.operand_key(LLVMGetOperand(inst, 0)),
                src: fctx.operand_key(LLVMGetOperand(inst, 1)),
                bytes: constant_u64(LLVMGetOperand(inst, 2)),
                loc: loc(inst),
            });
            lowering.bump_modeled(if callee.starts_with("llvm.memmove.") {
                "memmove"
            } else {
                "memcpy"
            });
            bump_missing_loc(lowering, "memcpy", inst);
        } else {
            lowering.bump_tainted("malformed_memory_intrinsic");
        }
        return true;
    }

    if callee.starts_with("llvm.memset.") {
        if LLVMGetNumArgOperands(inst) >= 3 {
            body.push(Stmt::Memset {
                dst: fctx.operand_key(LLVMGetOperand(inst, 0)),
                value: fctx.operand_key(LLVMGetOperand(inst, 1)),
                bytes: constant_u64(LLVMGetOperand(inst, 2)),
                loc: loc(inst),
            });
            lowering.bump_modeled("memset");
            bump_missing_loc(lowering, "memset", inst);
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
            call_operand_keys(fctx, inst),
            call_result_keys(fctx, inst),
            "varargs_intrinsic",
            loc(inst),
            lowering,
        );
        return true;
    }

    if (0..LLVMGetNumArgOperands(inst))
        .any(|index| is_pointer_like_type(LLVMTypeOf(LLVMGetOperand(inst, index))))
        || (LLVMGetTypeKind(LLVMTypeOf(inst)) != LLVMTypeKind::LLVMVoidTypeKind
            && is_pointer_like_type(LLVMTypeOf(inst)))
    {
        lowering.bump_tainted(format!("unknown_pointer_intrinsic:{callee}"));
        push_unknown(
            body,
            callee,
            call_operand_keys(fctx, inst),
            call_result_keys(fctx, inst),
            "unknown_pointer_intrinsic",
            loc(inst),
            lowering,
        );
    } else {
        lowering.bump_skipped(format!("unknown_non_pointer_intrinsic:{callee}"));
    }
    true
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
            volatile: false,
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
        if let Some(global) = operand_global_name(ctx, constant) {
            body.push(Stmt::GlobalRef {
                global,
                access: Access::Ref,
                volatile: false,
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
    let mut path = BTreeSet::new();
    lower_constant_expr_value_inner(ctx, constant, body, temp_ordinal, lowering, &mut path, 0)
}

unsafe fn lower_constant_expr_value_inner(
    ctx: &ModuleCtx,
    constant: LLVMValueRef,
    body: &mut Vec<Stmt>,
    temp_ordinal: &mut u64,
    lowering: &mut LoweringStats,
    path: &mut BTreeSet<usize>,
    depth: usize,
) -> String {
    if !LLVMIsAFunction(constant).is_null()
        || !LLVMIsAGlobalVariable(constant).is_null()
        || !LLVMIsAGlobalAlias(constant).is_null()
        || !LLVMIsAGlobalIFunc(constant).is_null()
    {
        let name = value_name(constant);
        return format!("@{}", resolve_symbol_name(ctx, &name).unwrap_or(name));
    }
    if depth >= MAX_CONSTANT_EXPR_LOWER_DEPTH || !path.insert(constant as usize) {
        let dest = global_init_temp(temp_ordinal);
        lowering.bump_tainted("global_initializer_constant_traversal_limit");
        push_unknown(
            body,
            "constant_expr:traversal_limit",
            constant_pointer_operand_keys(ctx, constant),
            vec![dest.clone()],
            "global_initializer_pointer_constant",
            None,
            lowering,
        );
        return dest;
    }
    let result = if !LLVMIsAConstantExpr(constant).is_null() {
        match LLVMGetConstOpcode(constant) {
            LLVMOpcode::LLVMBitCast | LLVMOpcode::LLVMAddrSpaceCast => {
                let source = lower_constant_expr_value_inner(
                    ctx,
                    LLVMGetOperand(constant, 0),
                    body,
                    temp_ordinal,
                    lowering,
                    path,
                    depth + 1,
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
                let base = lower_constant_expr_value_inner(
                    ctx,
                    LLVMGetOperand(constant, 0),
                    body,
                    temp_ordinal,
                    lowering,
                    path,
                    depth + 1,
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
                let source = lower_constant_expr_value_inner(
                    ctx,
                    LLVMGetOperand(constant, 0),
                    body,
                    temp_ordinal,
                    lowering,
                    path,
                    depth + 1,
                );
                let dest = global_init_temp(temp_ordinal);
                body.push(Stmt::PtrToInt {
                    dest: dest.clone(),
                    source,
                    comparison_only: false,
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
            LLVMOpcode::LLVMSelect => {
                let true_value = lower_constant_expr_value_inner(
                    ctx,
                    LLVMGetOperand(constant, 1),
                    body,
                    temp_ordinal,
                    lowering,
                    path,
                    depth + 1,
                );
                let false_value = lower_constant_expr_value_inner(
                    ctx,
                    LLVMGetOperand(constant, 2),
                    body,
                    temp_ordinal,
                    lowering,
                    path,
                    depth + 1,
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
            other => {
                let dest = global_init_temp(temp_ordinal);
                lowering.bump_tainted(format!(
                    "global_initializer_unmodeled_pointer_constant:{}",
                    opcode_key(other)
                ));
                push_unknown(
                    body,
                    format!("constant_expr:{}", opcode_key(other)),
                    constant_pointer_operand_keys(ctx, constant),
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
            constant_pointer_operand_keys(ctx, constant),
            vec![dest.clone()],
            "global_initializer_pointer_constant",
            None,
            lowering,
        );
        dest
    };
    path.remove(&(constant as usize));
    result
}

unsafe fn collect_address_taken(
    ctx: &ModuleCtx,
    globals: &[LLVMValueRef],
    aliases: &[LLVMValueRef],
    functions: &[LLVMValueRef],
) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for global in globals {
        let initializer = LLVMGetInitializer(*global);
        if !initializer.is_null() {
            collect_constant_func_refs(ctx, initializer, &mut out);
        }
    }
    for alias in aliases {
        let aliasee = LLVMAliasGetAliasee(*alias);
        if !aliasee.is_null() {
            collect_constant_func_refs(ctx, aliasee, &mut out);
        }
    }
    for function in functions {
        if LLVMHasPersonalityFn(*function) != 0 {
            collect_constant_func_refs(ctx, LLVMGetPersonalityFn(*function), &mut out);
        }
        let mut block = LLVMGetFirstBasicBlock(*function);
        while !block.is_null() {
            let mut inst = LLVMGetFirstInstruction(block);
            while !inst.is_null() {
                collect_inst_address_taken(ctx, inst, &mut out);
                inst = LLVMGetNextInstruction(inst);
            }
            block = LLVMGetNextBasicBlock(block);
        }
    }
    out
}

unsafe fn collect_inst_address_taken(
    ctx: &ModuleCtx,
    inst: LLVMValueRef,
    out: &mut BTreeSet<String>,
) {
    match LLVMGetInstructionOpcode(inst) {
        LLVMOpcode::LLVMCall | LLVMOpcode::LLVMInvoke | LLVMOpcode::LLVMCallBr => {
            let called = LLVMGetCalledValue(inst);
            if !LLVMIsAInlineAsm(called).is_null() {
                return;
            }
            if !matches!(
                direct_symbol_name(called).as_deref(),
                Some(name) if resolve_function_name(ctx, name).is_some()
            ) {
                collect_value_func_refs(ctx, called, out);
            }
            for index in 0..LLVMGetNumArgOperands(inst) {
                collect_value_func_refs(ctx, LLVMGetOperand(inst, index), out);
            }
        }
        LLVMOpcode::LLVMStore => {
            collect_value_func_refs(ctx, LLVMGetOperand(inst, 0), out);
            collect_value_func_refs(ctx, LLVMGetOperand(inst, 1), out);
        }
        // Any other instruction (select, phi, gep, insertvalue, ret, …) that names a
        // function constant as an operand takes that function's address.
        _ => {
            for index in 0..LLVMGetNumOperands(inst) {
                collect_value_func_refs(ctx, LLVMGetOperand(inst, index as u32), out);
            }
        }
    }
}

unsafe fn collect_value_func_refs(
    ctx: &ModuleCtx,
    value: LLVMValueRef,
    out: &mut BTreeSet<String>,
) {
    if !LLVMIsAConstant(value).is_null()
        || !LLVMIsAFunction(value).is_null()
        || !LLVMIsAGlobalAlias(value).is_null()
        || !LLVMIsAGlobalIFunc(value).is_null()
    {
        collect_constant_func_refs(ctx, value, out);
    }
}

unsafe fn collect_constant_func_refs(
    ctx: &ModuleCtx,
    constant: LLVMValueRef,
    out: &mut BTreeSet<String>,
) {
    let mut stack = vec![constant];
    let mut visited = BTreeSet::new();
    while let Some(value) = stack.pop() {
        if value.is_null() || !visited.insert(value as usize) {
            continue;
        }
        if let Some(name) = direct_symbol_name(value) {
            if let Some(resolved) = resolve_function_name(ctx, &name) {
                out.insert(resolved);
            }
            continue;
        }
        if constant_has_traversable_operands(value) {
            push_operands(value, &mut stack);
        }
    }
}

/// Collect the bare names of the global values (functions and global variables) directly
/// referenced by `global`'s constant initializer. Mirrors cclyzer's `constant_in_initializer`
/// (constant-init.dl), which recurses only through struct/array/vector *elements* — NOT
/// through `ConstantExpr` operands. So a direct element `@f` or `bitcast(@f)` is captured, but
/// a `getelementptr(@g, …)` element is not (the GEP expr is not itself a global-value
/// constant). Names preserve initializer (element) order, deduped; the owning global is
/// excluded. The `cc2json` client filters `.`-prefixed (string-constant) names downstream.
unsafe fn collect_global_init_refs(global: LLVMValueRef) -> Vec<String> {
    let initializer = LLVMGetInitializer(global);
    if initializer.is_null() {
        return Vec::new();
    }
    let owner = value_name(global);
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    collect_init_refs_rec(initializer, &owner, &mut out, &mut seen);
    out
}

unsafe fn collect_init_refs_rec(
    value: LLVMValueRef,
    owner: &str,
    out: &mut Vec<String>,
    seen: &mut BTreeSet<String>,
) {
    if value.is_null() {
        return;
    }
    // A direct global-value reference (peeking only through bitcast/addrspacecast, like
    // `direct_symbol_name`) is a leaf — record it and stop.
    if let Some(name) = direct_global_value_name(value) {
        if !name.is_empty() && name != owner && seen.insert(name.clone()) {
            out.push(name);
        }
        return;
    }
    // Otherwise recurse only into aggregate elements (struct/array/vector), never into
    // ConstantExpr operands (matching cclyzer's struct/array-only recursion).
    if !LLVMIsAConstantStruct(value).is_null()
        || !LLVMIsAConstantArray(value).is_null()
        || !LLVMIsAConstantVector(value).is_null()
    {
        let count = LLVMGetNumOperands(value);
        for index in 0..count {
            collect_init_refs_rec(LLVMGetOperand(value, index as u32), owner, out, seen);
        }
    }
}

/// Name of the global value (function, global variable, alias, or ifunc) a constant directly
/// denotes, seeing through `bitcast`/`addrspacecast` constant exprs only (not GEP). Extends
/// `direct_symbol_name`, which omits plain global variables.
unsafe fn direct_global_value_name(value: LLVMValueRef) -> Option<String> {
    let mut value = value;
    let mut visited = BTreeSet::new();
    loop {
        if value.is_null() || !visited.insert(value as usize) {
            return None;
        }
        if !LLVMIsAFunction(value).is_null()
            || !LLVMIsAGlobalVariable(value).is_null()
            || !LLVMIsAGlobalAlias(value).is_null()
            || !LLVMIsAGlobalIFunc(value).is_null()
        {
            return Some(value_name(value));
        }
        if !LLVMIsAConstantExpr(value).is_null() {
            match LLVMGetConstOpcode(value) {
                LLVMOpcode::LLVMBitCast | LLVMOpcode::LLVMAddrSpaceCast => {
                    value = LLVMGetOperand(value, 0);
                    continue;
                }
                _ => {}
            }
        }
        return None;
    }
}

unsafe fn lower_personality_function(
    ctx: &ModuleCtx,
    function: LLVMValueRef,
    lowering: &mut LoweringStats,
) {
    if LLVMHasPersonalityFn(function) == 0 {
        return;
    }
    let personality = LLVMGetPersonalityFn(function);
    if constant_has_pointer_flow(personality) {
        lowering.bump_tainted("personality_function");
        for operand in constant_pointer_operand_keys(ctx, personality) {
            lowering.bump_tainted(format!("personality_operand:{operand}"));
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
    let mut stack = vec![constant];
    let mut visited = BTreeSet::new();
    while let Some(value) = stack.pop() {
        if value.is_null() || !visited.insert(value as usize) {
            continue;
        }
        if !LLVMIsAConstantPointerNull(value).is_null()
            || !LLVMIsAConstantAggregateZero(value).is_null()
            || !LLVMIsAUndefValue(value).is_null()
            || !LLVMIsAPoisonValue(value).is_null()
        {
            continue;
        }
        if !LLVMIsAFunction(value).is_null()
            || !LLVMIsAGlobalVariable(value).is_null()
            || !LLVMIsAGlobalAlias(value).is_null()
            || !LLVMIsAGlobalIFunc(value).is_null()
        {
            return true;
        }
        if !LLVMIsAConstantExpr(value).is_null() {
            match LLVMGetConstOpcode(value) {
                LLVMOpcode::LLVMGetElementPtr | LLVMOpcode::LLVMIntToPtr => return true,
                _ if is_pointer_like_type(LLVMTypeOf(value)) => return true,
                _ => push_operands(value, &mut stack),
            }
            continue;
        }
        if constant_has_traversable_operands(value) {
            push_operands(value, &mut stack);
            continue;
        }
        if is_pointer_like_type(LLVMTypeOf(value)) {
            return true;
        }
    }
    false
}

unsafe fn constant_pointer_operand_keys(ctx: &ModuleCtx, constant: LLVMValueRef) -> Vec<String> {
    let mut out = BTreeSet::new();
    let mut stack = vec![constant];
    let mut visited = BTreeSet::new();
    collect_constant_pointer_operand_keys(ctx, &mut stack, &mut visited, &mut out);
    out.into_iter().collect()
}

unsafe fn collect_constant_pointer_operand_keys(
    ctx: &ModuleCtx,
    stack: &mut Vec<LLVMValueRef>,
    visited: &mut BTreeSet<usize>,
    out: &mut BTreeSet<String>,
) {
    while let Some(value) = stack.pop() {
        if value.is_null() || !visited.insert(value as usize) {
            continue;
        }
        if let Some(name) = direct_symbol_name(value) {
            let resolved = resolve_symbol_name(ctx, &name).unwrap_or(name);
            out.insert(format!("@{resolved}"));
            continue;
        }
        push_operands(value, stack);
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

unsafe fn call_result_key(fctx: &mut FunctionCtx, inst: LLVMValueRef) -> Option<String> {
    if LLVMGetTypeKind(LLVMTypeOf(inst)) == LLVMTypeKind::LLVMVoidTypeKind {
        None
    } else {
        Some(fctx.local_key(inst))
    }
}

unsafe fn direct_symbol_name(value: LLVMValueRef) -> Option<String> {
    let mut value = value;
    let mut visited = BTreeSet::new();
    loop {
        if value.is_null() || !visited.insert(value as usize) {
            return None;
        }
        if !LLVMIsAFunction(value).is_null()
            || !LLVMIsAGlobalAlias(value).is_null()
            || !LLVMIsAGlobalIFunc(value).is_null()
        {
            return Some(value_name(value));
        }
        if !LLVMIsAConstantExpr(value).is_null() {
            match LLVMGetConstOpcode(value) {
                LLVMOpcode::LLVMBitCast | LLVMOpcode::LLVMAddrSpaceCast => {
                    value = LLVMGetOperand(value, 0);
                    continue;
                }
                _ => {}
            }
        }
        return None;
    }
}

unsafe fn operand_global_name(ctx: &ModuleCtx, value: LLVMValueRef) -> Option<String> {
    let mut value = value;
    let mut visited = BTreeSet::new();
    loop {
        if value.is_null() || !visited.insert(value as usize) {
            return None;
        }
        if !LLVMIsAGlobalVariable(value).is_null() || !LLVMIsAGlobalAlias(value).is_null() {
            let name = value_name(value);
            return resolve_global_name(ctx, &name);
        }
        if !LLVMIsAConstantExpr(value).is_null() {
            match LLVMGetConstOpcode(value) {
                LLVMOpcode::LLVMBitCast
                | LLVMOpcode::LLVMAddrSpaceCast
                | LLVMOpcode::LLVMGetElementPtr => {
                    value = LLVMGetOperand(value, 0);
                    continue;
                }
                _ => {}
            }
        }
        return None;
    }
}

unsafe fn constant_has_traversable_operands(value: LLVMValueRef) -> bool {
    !LLVMIsAConstantStruct(value).is_null()
        || !LLVMIsAConstantArray(value).is_null()
        || !LLVMIsAConstantVector(value).is_null()
        || !LLVMIsAConstantDataArray(value).is_null()
        || !LLVMIsAConstantDataVector(value).is_null()
        || !LLVMIsAConstantExpr(value).is_null()
}

unsafe fn push_operands(value: LLVMValueRef, stack: &mut Vec<LLVMValueRef>) {
    let count = LLVMGetNumOperands(value);
    for index in (0..count).rev() {
        stack.push(LLVMGetOperand(value, index as u32));
    }
}

unsafe fn is_pointer_like_type(ty: LLVMTypeRef) -> bool {
    type_contains_pointer_shallow(ty)
}

unsafe fn is_pointer_vector_type(ty: LLVMTypeRef) -> bool {
    match LLVMGetTypeKind(ty) {
        LLVMTypeKind::LLVMVectorTypeKind => type_contains_pointer_shallow(LLVMGetElementType(ty)),
        _ => false,
    }
}

unsafe fn type_contains_pointer(ty: LLVMTypeRef) -> bool {
    let mut visited = BTreeSet::new();
    type_contains_pointer_impl(ty, &mut visited)
}

unsafe fn type_contains_pointer_impl(ty: LLVMTypeRef, visited: &mut BTreeSet<usize>) -> bool {
    if !visited.insert(ty as usize) {
        return false;
    }
    match LLVMGetTypeKind(ty) {
        LLVMTypeKind::LLVMPointerTypeKind => true,
        LLVMTypeKind::LLVMArrayTypeKind | LLVMTypeKind::LLVMVectorTypeKind => {
            type_contains_pointer_impl(LLVMGetElementType(ty), visited)
        }
        LLVMTypeKind::LLVMStructTypeKind => {
            if LLVMIsOpaqueStruct(ty) != 0 {
                return false;
            }
            let count = LLVMCountStructElementTypes(ty);
            let mut elements = vec![ptr::null_mut(); count as usize];
            LLVMGetStructElementTypes(ty, elements.as_mut_ptr());
            elements
                .into_iter()
                .any(|element| type_contains_pointer_impl(element, visited))
        }
        _ => false,
    }
}

unsafe fn type_contains_pointer_shallow(ty: LLVMTypeRef) -> bool {
    match LLVMGetTypeKind(ty) {
        LLVMTypeKind::LLVMPointerTypeKind => true,
        LLVMTypeKind::LLVMVectorTypeKind => type_contains_pointer_shallow(LLVMGetElementType(ty)),
        _ => false,
    }
}

unsafe fn loc(value: LLVMValueRef) -> Option<Loc> {
    let line = LLVMGetDebugLocLine(value);
    if line == 0 {
        return None;
    }
    let (dir, filename) = debug_loc_dir_filename(value);
    let file = join_dir_filename(&dir, &filename);
    Some(Loc {
        file,
        line,
        col: LLVMGetDebugLocColumn(value),
        dir: Some(dir),
        filename: Some(filename),
    })
}

/// Raw DWARF `(directory, filename)` for a debug location, exactly as cclyzer reads them via
/// `DIScope::getDirectory`/`getFilename`. The filename may itself contain `/`.
unsafe fn debug_loc_dir_filename(value: LLVMValueRef) -> (String, String) {
    let mut file_len = 0_u32;
    let file = LLVMGetDebugLocFilename(value, &mut file_len);
    let mut dir_len = 0_u32;
    let dir = LLVMGetDebugLocDirectory(value, &mut dir_len);
    (
        bytes_to_string(dir.cast(), dir_len as usize),
        bytes_to_string(file.cast(), file_len as usize),
    )
}

/// Join a DWARF directory and (relative) filename into a display path, matching the historical
/// `Loc::file` value.
fn join_dir_filename(dir: &str, filename: &str) -> String {
    if !dir.is_empty() && !filename.starts_with('/') {
        format!("{}/{}", dir.trim_end_matches('/'), filename)
    } else {
        filename.to_string()
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
    if LLVMIsAConstantInt(value).is_null() || LLVMGetIntTypeWidth(LLVMTypeOf(value)) > 64 {
        return None;
    }
    Some(LLVMConstIntGetSExtValue(value))
}

unsafe fn constant_u64(value: LLVMValueRef) -> Option<u64> {
    if LLVMIsAConstantInt(value).is_null() || LLVMGetIntTypeWidth(LLVMTypeOf(value)) > 64 {
        return None;
    }
    Some(LLVMConstIntGetZExtValue(value))
}

unsafe fn is_atomic_memory_inst(inst: LLVMValueRef) -> bool {
    LLVMGetOrdering(inst) != LLVMAtomicOrdering::LLVMAtomicOrderingNotAtomic
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

unsafe fn collect_alias_map(
    aliases: &[LLVMValueRef],
    func_names: &BTreeSet<String>,
    global_names: &BTreeSet<String>,
    lowering: &mut LoweringStats,
) -> AliasMap {
    let mut out = AliasMap::new();
    for alias in aliases {
        let alias_key = value_name(*alias);
        if !is_non_interposable_alias(*alias) {
            lowering.bump_tainted(format!("alias_interposable:{alias_key}"));
            continue;
        }
        let Some(target) = constant_symbol_name(LLVMAliasGetAliasee(*alias)) else {
            lowering.bump_tainted(format!("alias_unresolved:{alias_key}"));
            continue;
        };
        if func_names.contains(&target) {
            out.insert(alias_key, AliasTarget::Function(target));
            lowering.bump_modeled("alias_function_resolved");
        } else if global_names.contains(&target) {
            out.insert(alias_key, AliasTarget::Global(target));
            lowering.bump_modeled("alias_global_resolved");
        } else {
            lowering.bump_tainted(format!("alias_unresolved:{alias_key}"));
        }
    }
    out
}

unsafe fn is_non_interposable_alias(alias: LLVMValueRef) -> bool {
    matches!(
        LLVMGetLinkage(alias),
        LLVMLinkage::LLVMPrivateLinkage | LLVMLinkage::LLVMInternalLinkage
    )
}

unsafe fn constant_symbol_name(constant: LLVMValueRef) -> Option<String> {
    let mut value = constant;
    let mut visited = BTreeSet::new();
    loop {
        if value.is_null() || !visited.insert(value as usize) {
            return None;
        }
        if !LLVMIsAFunction(value).is_null()
            || !LLVMIsAGlobalVariable(value).is_null()
            || !LLVMIsAGlobalAlias(value).is_null()
            || !LLVMIsAGlobalIFunc(value).is_null()
        {
            return Some(value_name(value));
        }
        if !LLVMIsAConstantExpr(value).is_null() {
            match LLVMGetConstOpcode(value) {
                LLVMOpcode::LLVMBitCast
                | LLVMOpcode::LLVMAddrSpaceCast
                | LLVMOpcode::LLVMGetElementPtr => {
                    value = LLVMGetOperand(value, 0);
                    continue;
                }
                _ => {}
            }
        }
        return None;
    }
}

fn resolve_function_name(ctx: &ModuleCtx, name: &str) -> Option<String> {
    if ctx.func_names.contains(name) {
        Some(name.to_string())
    } else {
        match ctx.aliases.get(name) {
            Some(AliasTarget::Function(target)) => Some(target.clone()),
            _ => None,
        }
    }
}

fn resolve_global_name(ctx: &ModuleCtx, name: &str) -> Option<String> {
    if ctx.global_names.contains(name) {
        Some(name.to_string())
    } else {
        match ctx.aliases.get(name) {
            Some(AliasTarget::Global(target)) => Some(target.clone()),
            _ => None,
        }
    }
}

fn resolve_symbol_name(ctx: &ModuleCtx, name: &str) -> Option<String> {
    if ctx.func_names.contains(name)
        || ctx.global_names.contains(name)
        || ctx.ifunc_names.contains(name)
    {
        Some(name.to_string())
    } else {
        match ctx.aliases.get(name) {
            Some(AliasTarget::Function(target)) | Some(AliasTarget::Global(target)) => {
                Some(target.clone())
            }
            None => None,
        }
    }
}

unsafe fn opcode_key_for_inst(inst: LLVMValueRef, opcode: LLVMOpcode) -> &'static str {
    match opcode {
        LLVMOpcode::LLVMBr => {
            if LLVMGetNumOperands(inst) == 3 {
                "condbr"
            } else {
                "br"
            }
        }
        _ => opcode_key(opcode),
    }
}

fn opcode_key(opcode: LLVMOpcode) -> &'static str {
    match opcode {
        LLVMOpcode::LLVMRet => "ret",
        LLVMOpcode::LLVMBr => "br",
        LLVMOpcode::LLVMSwitch => "switch",
        LLVMOpcode::LLVMIndirectBr => "indirectbr",
        LLVMOpcode::LLVMInvoke => "invoke",
        LLVMOpcode::LLVMResume => "resume",
        LLVMOpcode::LLVMUnreachable => "unreachable",
        LLVMOpcode::LLVMCallBr => "callbr",
        LLVMOpcode::LLVMCleanupRet => "cleanupret",
        LLVMOpcode::LLVMCatchRet => "catchret",
        LLVMOpcode::LLVMCatchSwitch => "catchswitch",
        LLVMOpcode::LLVMAdd => "add",
        LLVMOpcode::LLVMSub => "sub",
        LLVMOpcode::LLVMMul => "mul",
        LLVMOpcode::LLVMUDiv => "udiv",
        LLVMOpcode::LLVMSDiv => "sdiv",
        LLVMOpcode::LLVMURem => "urem",
        LLVMOpcode::LLVMSRem => "srem",
        LLVMOpcode::LLVMAnd => "and",
        LLVMOpcode::LLVMOr => "or",
        LLVMOpcode::LLVMXor => "xor",
        LLVMOpcode::LLVMShl => "shl",
        LLVMOpcode::LLVMLShr => "lshr",
        LLVMOpcode::LLVMAShr => "ashr",
        LLVMOpcode::LLVMFAdd => "fadd",
        LLVMOpcode::LLVMFSub => "fsub",
        LLVMOpcode::LLVMFMul => "fmul",
        LLVMOpcode::LLVMFDiv => "fdiv",
        LLVMOpcode::LLVMFRem => "frem",
        LLVMOpcode::LLVMFNeg => "fneg",
        LLVMOpcode::LLVMAlloca => "alloca",
        LLVMOpcode::LLVMLoad => "load",
        LLVMOpcode::LLVMStore => "store",
        LLVMOpcode::LLVMGetElementPtr => "getelementptr",
        LLVMOpcode::LLVMTrunc => "trunc",
        LLVMOpcode::LLVMZExt => "zext",
        LLVMOpcode::LLVMSExt => "sext",
        LLVMOpcode::LLVMFPTrunc => "fptrunc",
        LLVMOpcode::LLVMFPExt => "fpext",
        LLVMOpcode::LLVMFPToUI => "fptoui",
        LLVMOpcode::LLVMFPToSI => "fptosi",
        LLVMOpcode::LLVMUIToFP => "uitofp",
        LLVMOpcode::LLVMSIToFP => "sitofp",
        LLVMOpcode::LLVMPtrToInt => "ptrtoint",
        LLVMOpcode::LLVMIntToPtr => "inttoptr",
        LLVMOpcode::LLVMBitCast => "bitcast",
        LLVMOpcode::LLVMAddrSpaceCast => "addrspacecast",
        LLVMOpcode::LLVMICmp => "icmp",
        LLVMOpcode::LLVMFCmp => "fcmp",
        LLVMOpcode::LLVMCall => "call",
        LLVMOpcode::LLVMFence => "fence",
        LLVMOpcode::LLVMPHI => "phi",
        LLVMOpcode::LLVMSelect => "select",
        LLVMOpcode::LLVMExtractElement => "extractelement",
        LLVMOpcode::LLVMInsertElement => "insertelement",
        LLVMOpcode::LLVMShuffleVector => "shufflevector",
        LLVMOpcode::LLVMExtractValue => "extractvalue",
        LLVMOpcode::LLVMInsertValue => "insertvalue",
        LLVMOpcode::LLVMFreeze => "freeze",
        LLVMOpcode::LLVMVAArg => "va_arg",
        LLVMOpcode::LLVMLandingPad => "landingpad",
        LLVMOpcode::LLVMCatchPad => "catchpad",
        LLVMOpcode::LLVMCleanupPad => "cleanuppad",
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

// ---------------------------------------------------------------------------------------
// M1.8 dynamic icall trace instrumentation.
//
// Inserts, before every *indirect* call, a call to the runtime hook
//   void __pangs_trace_icall(const char *caller, int32_t idx, void *target)
// where `idx` is the static index of this indirect call among the indirect calls of its
// function, in instruction order. `check-traces` maps (caller, idx) to the analysis's
// i-th indirect callsite for that caller — both sides count in the same order — so no
// callsite-key string has to be re-derived here (the named M1.8 correspondence risk).

use llvm_sys::bit_writer::LLVMWriteBitcodeToFile;

pub fn instrument_icalls(input: &Path, output: &Path) -> Result<usize, PirError> {
    let parsed = ParsedModule::from_path(input)?;
    let count = unsafe { instrument_module(parsed.module) };
    let out_str = output.display().to_string();
    let c_out = CString::new(out_str.clone()).map_err(|_| PirError::Llvm {
        path: out_str.clone(),
        message: "path contains interior NUL".to_string(),
    })?;
    let rc = unsafe { LLVMWriteBitcodeToFile(parsed.module, c_out.as_ptr()) };
    if rc != 0 {
        return Err(PirError::Llvm {
            path: out_str,
            message: "failed to write instrumented bitcode".to_string(),
        });
    }
    Ok(count)
}

unsafe fn instrument_module(module: LLVMModuleRef) -> usize {
    let context = LLVMGetModuleContext(module);
    let i8_ty = LLVMInt8TypeInContext(context);
    let i8_ptr = LLVMPointerType(i8_ty, 0);
    let i32_ty = LLVMInt32TypeInContext(context);
    let void_ty = LLVMVoidTypeInContext(context);
    let mut params = [i8_ptr, i32_ty, i8_ptr];
    let hook_ty = LLVMFunctionType(void_ty, params.as_mut_ptr(), params.len() as u32, 0);

    let hook_name = CString::new("__pangs_trace_icall").unwrap();
    let mut hook = LLVMGetNamedFunction(module, hook_name.as_ptr());
    if hook.is_null() {
        hook = LLVMAddFunction(module, hook_name.as_ptr(), hook_ty);
    }

    let builder = LLVMCreateBuilderInContext(context);
    let mut total = 0usize;

    let mut function = LLVMGetFirstFunction(module);
    while !function.is_null() {
        if LLVMCountBasicBlocks(function) != 0 {
            let caller = value_name(function);
            let mut idx: u64 = 0;
            let mut block = LLVMGetFirstBasicBlock(function);
            while !block.is_null() {
                let mut inst = LLVMGetFirstInstruction(block);
                while !inst.is_null() {
                    if is_indirect_call(inst) {
                        emit_trace(builder, hook, hook_ty, i8_ptr, i32_ty, inst, &caller, idx);
                        idx += 1;
                        total += 1;
                    }
                    inst = LLVMGetNextInstruction(inst);
                }
                block = LLVMGetNextBasicBlock(block);
            }
        }
        function = LLVMGetNextFunction(function);
    }

    LLVMDisposeBuilder(builder);
    total
}

unsafe fn is_indirect_call(inst: LLVMValueRef) -> bool {
    match LLVMGetInstructionOpcode(inst) {
        LLVMOpcode::LLVMCall | LLVMOpcode::LLVMInvoke | LLVMOpcode::LLVMCallBr => {
            let called = LLVMGetCalledValue(inst);
            // Indirect iff the callee is neither inline asm nor a direct function symbol.
            LLVMIsAInlineAsm(called).is_null() && LLVMIsAFunction(called).is_null()
        }
        _ => false,
    }
}

unsafe fn emit_trace(
    builder: LLVMBuilderRef,
    hook: LLVMValueRef,
    hook_ty: LLVMTypeRef,
    i8_ptr: LLVMTypeRef,
    i32_ty: LLVMTypeRef,
    inst: LLVMValueRef,
    caller: &str,
    idx: u64,
) {
    LLVMPositionBuilderBefore(builder, inst);
    let caller_c = CString::new(caller).unwrap_or_else(|_| CString::new("?").unwrap());
    let name = CString::new("pangs_caller").unwrap();
    let caller_ptr = LLVMBuildGlobalStringPtr(builder, caller_c.as_ptr(), name.as_ptr());
    let idx_const = LLVMConstInt(i32_ty, idx, 0);
    let called = LLVMGetCalledValue(inst);
    let cast_name = CString::new("pangs_tgt").unwrap();
    let target_ptr = LLVMBuildPointerCast(builder, called, i8_ptr, cast_name.as_ptr());
    let mut args = [caller_ptr, idx_const, target_ptr];
    let empty = CString::new("").unwrap();
    LLVMBuildCall2(
        builder,
        hook_ty,
        hook,
        args.as_mut_ptr(),
        args.len() as u32,
        empty.as_ptr(),
    );
}
