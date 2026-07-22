use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

mod llvm_sys;

/// Exact-name external functions whose nullable pointer result is derived from one pointer
/// argument. These shared semantic facts are consumed by PAG boundary modeling and structural
/// pointer-provenance validation in the LLVM front end.
pub fn external_return_alias_arg(callee: &str) -> Option<usize> {
    matches!(
        callee.strip_prefix('@').unwrap_or(callee),
        "strchr" | "strrchr" | "strstr" | "strpbrk" | "memchr"
    )
    .then_some(0)
}

/// Instrument every indirect call in an LLVM `.bc`/`.ll` module with a runtime trace hook
/// and write the result to `output` (M1.8 dynamic icall validation). Returns the number of
/// instrumented sites.
pub fn instrument_icalls(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
) -> Result<usize, PirError> {
    llvm_sys::instrument_icalls(input.as_ref(), output.as_ref())
}

#[derive(Debug, Error)]
pub enum PirError {
    #[error("failed to read PIR input {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse PIR JSON {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to parse LLVM IR {path}: {message}")]
    Llvm { path: String, message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pir {
    pub module: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "LoweringStats::is_empty")]
    pub lowering: LoweringStats,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetInfo>,
    #[serde(default)]
    pub functions: Vec<Func>,
    #[serde(default)]
    pub globals: Vec<Global>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub global_init: Vec<Stmt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetInfo {
    pub triple: String,
    pub data_layout: String,
    pub supported_atomic_widths: Vec<u64>,
}

impl Pir {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, PirError> {
        let path = path.as_ref();
        if matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("bc" | "ll")
        ) {
            return llvm_sys::lower_path(path, None);
        }
        let data = fs::read_to_string(path).map_err(|source| PirError::Read {
            path: path.display().to_string(),
            source,
        })?;
        serde_json::from_str(&data).map_err(|source| PirError::Parse {
            path: path.display().to_string(),
            source,
        })
    }

    pub fn from_path_with_repo_root(
        path: impl AsRef<Path>,
        repo_root: impl AsRef<Path>,
    ) -> Result<Self, PirError> {
        let path = path.as_ref();
        if matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("bc" | "ll")
        ) {
            return llvm_sys::lower_path(path, Some(repo_root.as_ref()));
        }
        Self::from_path(path)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Func {
    pub key: String,
    pub sig: Signature,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub param_names: Vec<String>,
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub line: Option<u32>,
    #[serde(default)]
    pub external: bool,
    #[serde(default)]
    pub exported: bool,
    #[serde(default)]
    pub address_taken: bool,
    #[serde(default)]
    pub body: Vec<Stmt>,
}

impl Func {
    pub fn vararg(&self) -> bool {
        self.sig.vararg
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Global {
    pub key: String,
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub line: Option<u32>,
    #[serde(default)]
    pub is_const: bool,
    #[serde(default = "default_true")]
    pub mutable: bool,
    #[serde(default)]
    pub exported: bool,
    #[serde(default = "default_true")]
    pub is_definition: bool,
    #[serde(default)]
    pub linkage: SymbolLinkage,
    #[serde(default)]
    pub type_spelling: Option<String>,
    #[serde(default)]
    pub size_bits: Option<u64>,
    #[serde(default)]
    pub align_bits: Option<u64>,
    #[serde(default)]
    pub path_error: Option<String>,
    #[serde(default)]
    pub scalar_class: Option<ScalarTypeClass>,
    #[serde(default)]
    pub signed: Option<bool>,
    /// The definition's typed LLVM constant initializer (for example, `i32 0`).
    /// Declarations have no initializer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initializer_ir: Option<String>,
    /// Names of other global values (functions and global variables) referenced by this
    /// global's constant initializer, walked recursively through struct/array/expr
    /// constants. Mirrors cclyzer's `global_initializer_references` (constant-init.dl) and
    /// feeds the `cc2json` client. Names are bare (no leading `@`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub init_refs: Vec<String>,
}

impl Default for Global {
    fn default() -> Self {
        Self {
            key: String::new(),
            file: None,
            line: None,
            is_const: false,
            mutable: true,
            exported: false,
            is_definition: true,
            linkage: SymbolLinkage::External,
            type_spelling: None,
            size_bits: None,
            align_bits: None,
            path_error: None,
            scalar_class: None,
            signed: None,
            initializer_ir: None,
            init_refs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolLinkage {
    Internal,
    #[default]
    External,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScalarTypeClass {
    Integer,
    Boolean,
    Enum,
    Pointer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScalarOp {
    Add,
    Sub,
    And,
    Or,
    Xor,
}

/// The vararg slots that may be read by one statically recognized `va_arg` operation.
/// `From` is used when the operation is in a loop and can consume every remaining slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VarArgPosition {
    Exact { index: u32 },
    From { index: u32 },
}

fn default_true() -> bool {
    true
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Stmt {
    Alloca {
        dest: String,
        ty: String,
        #[serde(default)]
        loc: Option<Loc>,
    },
    Assign {
        dest: String,
        #[serde(default)]
        sources: Vec<String>,
        #[serde(default)]
        loc: Option<Loc>,
    },
    ScalarOp {
        dest: String,
        op: ScalarOp,
        lhs: String,
        rhs: String,
        #[serde(default)]
        loc: Option<Loc>,
    },
    Load {
        dest: String,
        address: String,
        #[serde(default)]
        loc: Option<Loc>,
    },
    Store {
        address: String,
        value: String,
        #[serde(default)]
        loc: Option<Loc>,
    },
    Gep {
        dest: String,
        base: String,
        #[serde(default)]
        byte_off: Option<i64>,
        #[serde(default)]
        loc: Option<Loc>,
    },
    PtrToInt {
        dest: String,
        source: String,
        /// Legacy serialized spelling for a conversion whose integer use was proved innocuous:
        /// either a closed comparison computation or one operand of a relocation-invariant
        /// pointer difference with a common structural provenance root.
        #[serde(default, skip_serializing_if = "is_false")]
        comparison_only: bool,
        #[serde(default)]
        loc: Option<Loc>,
    },
    IntToPtr {
        dest: String,
        source: String,
        #[serde(default)]
        loc: Option<Loc>,
    },
    /// A proven ABI lowering of `va_arg`. The ordinary LLVM instructions remain in the PIR, but
    /// this statement supplies the precise callsite-to-result relation used by the PAG.
    VarArg {
        dest: String,
        position: VarArgPosition,
        #[serde(default)]
        loc: Option<Loc>,
    },
    Memcpy {
        dst: String,
        src: String,
        #[serde(default)]
        bytes: Option<u64>,
        /// The LLVM lowerer proved that this is an exact-size copy from a local aggregate
        /// whose every function-pointer field is initialized by a concrete function or null.
        /// Hand-written PIR and unrecognized LLVM patterns remain false and fail closed.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        proven_fnptr_init: bool,
        #[serde(default)]
        loc: Option<Loc>,
    },
    Memset {
        dst: String,
        value: String,
        #[serde(default)]
        bytes: Option<u64>,
        #[serde(default)]
        loc: Option<Loc>,
    },
    Unknown {
        op: String,
        #[serde(default)]
        operands: Vec<String>,
        #[serde(default)]
        results: Vec<String>,
        reason: String,
        #[serde(default)]
        loc: Option<Loc>,
    },
    Return {
        #[serde(default)]
        value: Option<String>,
        #[serde(default)]
        loc: Option<Loc>,
    },
    CallDirect {
        callee: String,
        sig: Signature,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        dest: Option<String>,
        #[serde(default)]
        loc: Option<Loc>,
    },
    CallIndirect {
        operand: String,
        sig: Signature,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        dest: Option<String>,
        #[serde(default)]
        loc: Option<Loc>,
    },
    GlobalRef {
        global: String,
        access: Access,
        #[serde(default, skip_serializing_if = "is_false")]
        volatile: bool,
        #[serde(default)]
        loc: Option<Loc>,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoweringStats {
    #[serde(default)]
    pub functions: u64,
    #[serde(default)]
    pub declarations: u64,
    #[serde(default)]
    pub globals: u64,
    #[serde(default)]
    pub aliases: u64,
    #[serde(default)]
    pub ifuncs: u64,
    #[serde(default)]
    pub instruction_counts: BTreeMap<String, u64>,
    #[serde(default)]
    pub terminator_counts: BTreeMap<String, u64>,
    #[serde(default)]
    pub modeled_counts: BTreeMap<String, u64>,
    #[serde(default)]
    pub skipped_counts: BTreeMap<String, u64>,
    #[serde(default)]
    pub tainted_counts: BTreeMap<String, u64>,
    #[serde(default)]
    pub missing_debug_locations: BTreeMap<String, u64>,
    #[serde(default)]
    pub non_ccc_calling_conventions: BTreeMap<String, u64>,
    /// Statement-boundary CFGs used by the phase-stationarity post-pass. Kept in the in-process
    /// PIR but omitted when `LoweringStats` is embedded in exported analysis metrics; hand-written
    /// PIR fixtures may still deserialize this field.
    #[serde(default, skip_serializing)]
    pub statement_cfgs: BTreeMap<String, StatementCfg>,
}

/// Source-oriented CFG for one defined function. Each node is the boundary immediately before
/// one contiguous debug-location statement group. Its `stmt_indices` refer to `Func::body`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatementCfg {
    pub entry: u32,
    #[serde(default)]
    pub boundaries: Vec<StatementBoundary>,
    /// True when the function has debug information and at least one unambiguous insertion point.
    /// Individual ambiguous boundaries remain in the CFG but carry `insertable: false`.
    #[serde(default)]
    pub source_mapping_available: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatementBoundary {
    pub id: u32,
    pub block: u32,
    pub ordinal: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loc: Option<Loc>,
    #[serde(default)]
    pub insertable: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stmt_indices: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub successors: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub predecessors: Vec<u32>,
}

impl LoweringStats {
    pub fn is_empty(&self) -> bool {
        self.functions == 0
            && self.declarations == 0
            && self.globals == 0
            && self.aliases == 0
            && self.ifuncs == 0
            && self.instruction_counts.is_empty()
            && self.terminator_counts.is_empty()
            && self.modeled_counts.is_empty()
            && self.skipped_counts.is_empty()
            && self.tainted_counts.is_empty()
            && self.missing_debug_locations.is_empty()
            && self.non_ccc_calling_conventions.is_empty()
    }

    pub fn bump_instruction(&mut self, op: impl Into<String>) {
        bump(&mut self.instruction_counts, op);
    }

    pub fn bump_terminator(&mut self, op: impl Into<String>) {
        bump(&mut self.terminator_counts, op);
    }

    pub fn bump_modeled(&mut self, op: impl Into<String>) {
        bump(&mut self.modeled_counts, op);
    }

    pub fn bump_skipped(&mut self, reason: impl Into<String>) {
        bump(&mut self.skipped_counts, reason);
    }

    pub fn bump_tainted(&mut self, reason: impl Into<String>) {
        bump(&mut self.tainted_counts, reason);
    }

    pub fn bump_missing_debug_location(&mut self, kind: impl Into<String>) {
        bump(&mut self.missing_debug_locations, kind);
    }

    pub fn bump_non_ccc(&mut self, cc: impl Into<String>) {
        bump(&mut self.non_ccc_calling_conventions, cc);
    }
}

fn bump(map: &mut BTreeMap<String, u64>, key: impl Into<String>) {
    *map.entry(key.into()).or_default() += 1;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Ref,
    Mod,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Loc {
    /// Joined display path: the DWARF directory and filename combined (the historical behavior,
    /// used by witness strings).
    pub file: String,
    pub line: u32,
    pub col: u32,
    /// Raw DWARF directory (`DIScope::getDirectory`), preserved separately so consumers can
    /// reconstruct the (directory, filename) pair without guessing where the boundary falls (the
    /// filename itself may contain `/`). `None` for PIR loaded from JSON without these fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
    /// Raw DWARF filename (`DIScope::getFilename`), which may include directory separators.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub ret: AbiClass,
    #[serde(default)]
    pub params: Vec<Param>,
    #[serde(default)]
    pub vararg: bool,
    #[serde(default = "default_cc")]
    pub cc: String,
}

fn default_cc() -> String {
    "ccc".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "class", rename_all = "snake_case")]
pub enum Param {
    Integer,
    Sse,
    X87,
    Fp128,
    Void,
    Byval { size: u64 },
    Sret { size: u64 },
}

impl Param {
    pub fn class(&self) -> AbiClass {
        match self {
            Param::Integer => AbiClass::Integer,
            Param::Sse => AbiClass::Sse,
            Param::X87 => AbiClass::X87,
            Param::Fp128 => AbiClass::Fp128,
            Param::Void => AbiClass::Void,
            Param::Byval { size } => AbiClass::Byval { size: *size },
            Param::Sret { size } => AbiClass::Sret { size: *size },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "class", rename_all = "snake_case")]
pub enum AbiClass {
    Integer,
    Sse,
    X87,
    Fp128,
    Void,
    Byval { size: u64 },
    Sret { size: u64 },
}

pub fn fsa_compatible(site: &Signature, callee: &Signature) -> bool {
    if site.cc != callee.cc {
        return false;
    }

    let site_n = site.params.len();
    let callee_n = callee.params.len();
    if callee.vararg {
        if callee_n > site_n {
            return false;
        }
    } else if callee_n > site_n {
        return false;
    }

    for (left, right) in site.params.iter().zip(callee.params.iter()) {
        if left.class() != right.class() {
            return false;
        }
    }

    site.ret == callee.ret
        || matches!(site.ret, AbiClass::Void)
        || matches!(callee.ret, AbiClass::Void)
}
