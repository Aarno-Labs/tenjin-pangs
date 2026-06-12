use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

mod llvm;

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
    #[serde(default)]
    pub functions: Vec<Func>,
    #[serde(default)]
    pub globals: Vec<Global>,
}

impl Pir {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, PirError> {
        let path = path.as_ref();
        if matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("bc" | "ll")
        ) {
            return llvm::lower_path(path);
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Func {
    pub key: String,
    pub sig: Signature,
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
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Stmt {
    CallDirect {
        callee: String,
        sig: Signature,
        #[serde(default)]
        loc: Option<Loc>,
    },
    CallIndirect {
        operand: String,
        sig: Signature,
        #[serde(default)]
        loc: Option<Loc>,
    },
    GlobalRef {
        global: String,
        access: Access,
        #[serde(default)]
        loc: Option<Loc>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Ref,
    Mod,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Loc {
    pub file: String,
    pub line: u32,
    pub col: u32,
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
