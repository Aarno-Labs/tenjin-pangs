use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const SCHEMA_VERSION: u32 = 3;
pub type Extra = BTreeMap<String, Value>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid symbol key: {0}")]
    InvalidKey(String),
    #[error("unsupported disposition manifest schema version {found} (maximum {supported})")]
    NewerSchema { found: u32, supported: u32 },
    #[error("marker collision for {marker}: {first} and {second}")]
    MarkerCollision {
        marker: String,
        first: String,
        second: String,
    },
    #[error("audit record id collision: {0}")]
    AuditIdCollision(String),
    #[error("invalid evidenced boolean {fact}: witness presence does not match value {value}")]
    InvalidEvidence { fact: String, value: bool },
    #[error("invalid disposition manifest invariant: {0}")]
    InvalidInvariant(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key {
    tu_path: Option<String>,
    symbol: String,
}

impl Key {
    pub fn new(tu_path: impl Into<String>, symbol: impl Into<String>) -> Result<Self, Error> {
        let key = Self {
            tu_path: Some(tu_path.into()),
            symbol: symbol.into(),
        };
        key.validate()?;
        Ok(key)
    }

    /// Construct a key for a globally unique symbol whose defining source file is
    /// unavailable. The pipeline's static-variable uniquification invariant makes
    /// this identity safe; manifest validation remains the collision backstop.
    pub fn unqualified(symbol: impl Into<String>) -> Result<Self, Error> {
        let key = Self {
            tu_path: None,
            symbol: symbol.into(),
        };
        key.validate()?;
        Ok(key)
    }

    pub fn parse(raw: &str) -> Result<Self, Error> {
        match raw.rsplit_once("::") {
            Some((tu_path, symbol)) => Self::new(tu_path, symbol),
            None => Self::unqualified(raw),
        }
        .map_err(|_| Error::InvalidKey(raw.to_owned()))
    }

    pub fn tu_path(&self) -> Option<&str> {
        self.tu_path.as_deref()
    }

    pub fn symbol(&self) -> &str {
        &self.symbol
    }

    fn validate(&self) -> Result<(), Error> {
        let path_ok = self.tu_path.as_ref().is_none_or(|tu_path| {
            !tu_path.is_empty()
                && !tu_path.starts_with('/')
                && !tu_path.starts_with("./")
                && !tu_path.contains("::")
                && !tu_path.contains('\\')
                && tu_path
                    .split('/')
                    .all(|part| !part.is_empty() && part != "." && part != "..")
        });
        let symbol_ok = !self.symbol.is_empty()
            && self
                .symbol
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'$'));
        if path_ok && symbol_ok {
            Ok(())
        } else {
            Err(Error::InvalidKey(self.to_string()))
        }
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(tu_path) = &self.tu_path {
            write!(f, "{tu_path}::{}", self.symbol)
        } else {
            f.write_str(&self.symbol)
        }
    }
}

impl Serialize for Key {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Key {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Strategy {
    Immutable,
    OnceLock,
    Atomic,
    Mutex,
    Localize,
    Unhandled,
}

impl Strategy {
    pub const DEFAULT_APPLICATION: [Self; 5] = [
        Self::Immutable,
        Self::OnceLock,
        Self::Atomic,
        Self::Mutex,
        Self::Localize,
    ];
    pub const DEFAULT_LIBRARY: [Self; 4] =
        [Self::Immutable, Self::OnceLock, Self::Atomic, Self::Mutex];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Immutable => "immutable",
            Self::OnceLock => "once-lock",
            Self::Atomic => "atomic",
            Self::Mutex => "mutex",
            Self::Localize => "localize",
            Self::Unhandled => "unhandled",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisposeMode {
    Application,
    Library,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Site {
    pub file: String,
    pub line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub col: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Witness {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site: Option<Site>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidencedBool {
    pub value: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<Witness>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl EvidencedBool {
    pub fn validate(&self, fact: &str, evidenced_polarity: bool) -> Result<(), Error> {
        if self.witness.is_some() == (self.value == evidenced_polarity) {
            Ok(())
        } else {
            Err(Error::InvalidEvidence {
                fact: fact.to_owned(),
                value: self.value,
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WordSizedScalar {
    pub value: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_spelling: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bits: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<ScalarClass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed: Option<bool>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScalarClass {
    Integer,
    Boolean,
    Enum,
    Pointer,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Certificate {
    Certified {
        certificate: Value,
        #[serde(flatten)]
        extra: Extra,
    },
    Failed {
        codes: Vec<String>,
        witnesses: Vec<Witness>,
        #[serde(skip_serializing_if = "Option::is_none")]
        recipe: Option<Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        diagnostics: Option<Value>,
        #[serde(flatten)]
        extra: Extra,
    },
}

impl Certificate {
    pub fn is_certified(&self) -> bool {
        matches!(self, Self::Certified { .. })
    }

    pub fn has_recipe(&self) -> bool {
        match self {
            Self::Certified { .. } => true,
            Self::Failed { recipe, .. } => recipe.is_some(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocalizationBlocker {
    pub code: String,
    pub witness: Witness,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalizationVerdict {
    Ok,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Localization {
    pub component: String,
    pub verdict: LocalizationVerdict,
    pub blockers: Vec<LocalizationBlocker>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Facts {
    pub written: EvidencedBool,
    pub omega_escaped_address: EvidencedBool,
    pub violation_taint: EvidencedBool,
    pub thread_visible: EvidencedBool,
    pub signal_context_access: EvidencedBool,
    pub access_set_complete: EvidencedBool,
    pub word_sized_scalar: WordSizedScalar,
    pub phase_stationarity: Option<Certificate>,
    pub atomic_eligibility: Option<Certificate>,
    pub mutex_eligibility: Option<Certificate>,
    pub coupling_group: Option<String>,
    pub localization: Option<Localization>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl Facts {
    pub fn validate(&self) -> Result<(), Error> {
        self.written.validate("written", true)?;
        self.omega_escaped_address
            .validate("omega_escaped_address", true)?;
        self.violation_taint.validate("violation_taint", true)?;
        self.thread_visible.validate("thread_visible", true)?;
        self.signal_context_access
            .validate("signal_context_access", true)?;
        self.access_set_complete
            .validate("access_set_complete", false)?;
        let scalar_detail_present = self.word_sized_scalar.type_spelling.is_some()
            || self.word_sized_scalar.size_bits.is_some()
            || self.word_sized_scalar.class.is_some()
            || self.word_sized_scalar.signed.is_some();
        if self.word_sized_scalar.value
            != (self.word_sized_scalar.type_spelling.is_some()
                && self.word_sized_scalar.size_bits.is_some()
                && self.word_sized_scalar.class.is_some())
            || (!self.word_sized_scalar.value && scalar_detail_present)
        {
            return Err(Error::InvalidInvariant(
                "word_sized_scalar detail presence does not match value".into(),
            ));
        }
        for (name, slot) in [
            ("phase_stationarity", &self.phase_stationarity),
            ("atomic_eligibility", &self.atomic_eligibility),
            ("mutex_eligibility", &self.mutex_eligibility),
        ] {
            if let Some(Certificate::Failed {
                codes, witnesses, ..
            }) = slot
            {
                if codes.is_empty() || witnesses.len() < codes.len() {
                    return Err(Error::InvalidInvariant(format!(
                        "{name} failure must have at least one witness per code"
                    )));
                }
            }
        }
        if let Some(localization) = &self.localization {
            let blockers_expected = localization.verdict == LocalizationVerdict::Blocked;
            if blockers_expected == localization.blockers.is_empty() {
                return Err(Error::InvalidInvariant(
                    "localization blockers must be non-empty exactly when blocked".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Meta {
    pub linkage: Linkage,
    pub type_spelling: Option<String>,
    pub size_bits: Option<u64>,
    pub align_bits: Option<u64>,
    pub llvm_name: String,
    pub file: Option<String>,
    pub line: Option<u32>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Linkage {
    Internal,
    External,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CascadeSkip {
    pub strategy: Strategy,
    pub reason: SkipReason,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SkipReason {
    GuardFailed {
        failed: Vec<String>,
        #[serde(flatten)]
        extra: Extra,
    },
    FactNotComputed {
        fact: String,
        #[serde(flatten)]
        extra: Extra,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DispositionProvenance {
    Cascade,
    Override,
    OverrideAcceptedRisk,
    GroupConstraint,
    Demoted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OverrideEcho {
    pub disposition: Strategy,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub accept_risk: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Demotion {
    pub from: Strategy,
    pub witness: Witness,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Disposition {
    pub chosen: Strategy,
    pub cascade_chosen: Strategy,
    pub provenance: DispositionProvenance,
    pub cascade_trace: Vec<CascadeSkip>,
    pub r#override: Option<OverrideEcho>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub demotion: Option<Demotion>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GlobalRecord {
    pub key: Key,
    pub meta: Meta,
    pub facts: Facts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disposition: Option<Disposition>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnkeyedGlobal {
    pub llvm_name: String,
    pub witness: Witness,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceEdge {
    pub kind: EvidenceKind,
    pub members: Vec<Key>,
    pub sites: Vec<Site>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    CoWrite,
    OncelockInterval,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OnceLockGroupSupport {
    Supported {
        supported: AlwaysTrue,
        publication_function: Key,
        common_interval: CommonInterval,
        common_p: Site,
        #[serde(flatten)]
        extra: Extra,
    },
    Unsupported {
        supported: AlwaysFalse,
        witness: Witness,
        #[serde(flatten)]
        extra: Extra,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlwaysTrue(pub bool);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlwaysFalse(pub bool);

macro_rules! literal_bool {
    ($ty:ty, $expected:expr) => {
        impl Serialize for $ty {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_bool($expected)
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = bool::deserialize(deserializer)?;
                if value == $expected {
                    Ok(Self(value))
                } else {
                    Err(serde::de::Error::custom(concat!(
                        "expected ",
                        stringify!($expected)
                    )))
                }
            }
        }
    };
}

literal_bool!(AlwaysTrue, true);
literal_bool!(AlwaysFalse, false);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommonInterval {
    pub earliest: Site,
    pub latest: Site,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroupStrategySupport {
    pub once_lock: Option<OnceLockGroupSupport>,
    pub mutex: Option<Value>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupProvenance {
    Cascade,
    Override,
    OverrideAcceptedRisk,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CouplingGroup {
    pub id: String,
    pub members: Vec<Key>,
    pub evidence: Vec<EvidenceEdge>,
    pub strategy_support: GroupStrategySupport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_disposition: Option<Strategy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_provenance: Option<GroupProvenance>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#override: Option<OverrideEcho>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisRun {
    pub pangs_git: String,
    pub llvm_version: String,
    pub input_path: String,
    pub input_sha256: String,
    pub opts: Value,
    pub repo_root: String,
    pub target_triple: String,
    pub data_layout: String,
    pub supported_atomic_widths: Vec<u64>,
    pub entry_spine: Option<Value>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DisposeRun {
    pub mode: DisposeMode,
    pub cascade: Vec<Strategy>,
    pub overrides_file: Option<String>,
    pub overrides_sha256: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunHeader {
    pub analysis: AnalysisRun,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dispose: Option<DisposeRun>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GuardFailure {
    pub member: Key,
    pub guard: String,
    pub witness: Witness,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OverrideOutcome {
    Honored,
    HonoredAcceptedRisk,
    Rejected,
    RejectedStrategyDisabled,
    RejectedStrategyUnavailable,
    RejectedNoRecipe,
    UnmatchedKey,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OverrideRequested {
    Strategy(Strategy),
    Order(Vec<Strategy>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverrideScope {
    Global,
    Group,
    Cascade,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OverrideReportEntry {
    pub scope: OverrideScope,
    pub key: Option<String>,
    pub requested: OverrideRequested,
    pub accept_risk: bool,
    pub outcome: OverrideOutcome,
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<Witness>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failures: Option<Vec<GuardFailure>>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OverrideCounts {
    pub honored: u64,
    pub honored_accepted_risk: u64,
    pub rejected: u64,
    pub rejected_strategy_disabled: u64,
    pub rejected_strategy_unavailable: u64,
    pub rejected_no_recipe: u64,
    pub unmatched_key: u64,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OverrideReport {
    pub entries: Vec<OverrideReportEntry>,
    pub counts: OverrideCounts,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MarkerInventoryEntry {
    pub key: Key,
    pub kind: String,
    pub marker: String,
    pub group: Option<String>,
    pub insertion: Site,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Materialization {
    pub tool: ToolInfo,
    pub marker_inventory: Vec<MarkerInventoryEntry>,
    pub demotions: Vec<MaterializationDemotion>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MaterializationDemotion {
    pub key: Key,
    pub from: Strategy,
    pub witness: Witness,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub run: RunHeader,
    pub globals: Vec<GlobalRecord>,
    pub unkeyed_globals: Vec<UnkeyedGlobal>,
    pub coupling_groups: Vec<CouplingGroup>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub override_report: Option<OverrideReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub materialization: Option<Materialization>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl Manifest {
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version > SCHEMA_VERSION {
            return Err(Error::NewerSchema {
                found: self.schema_version,
                supported: SCHEMA_VERSION,
            });
        }
        let mut global_keys = BTreeSet::new();
        for global in &self.globals {
            if !global_keys.insert(global.key.clone()) {
                return Err(Error::InvalidInvariant(format!(
                    "duplicate global key {}",
                    global.key
                )));
            }
            global.facts.validate()?;
        }
        let mut group_ids = BTreeSet::new();
        for group in &self.coupling_groups {
            if !group_ids.insert(&group.id) {
                return Err(Error::InvalidInvariant(format!(
                    "duplicate coupling group id {}",
                    group.id
                )));
            }
            for member in &group.members {
                if !global_keys.contains(member) {
                    return Err(Error::InvalidInvariant(format!(
                        "coupling group {} names absent member {member}",
                        group.id
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn canonicalize(&mut self) {
        self.globals.sort_by(|a, b| a.key.cmp(&b.key));
        for global in &mut self.globals {
            canonicalize_facts(&mut global.facts);
        }
        self.unkeyed_globals.sort_by(|a, b| {
            a.llvm_name
                .cmp(&b.llvm_name)
                .then_with(|| witness_cmp(&a.witness, &b.witness))
        });
        self.coupling_groups.sort_by(|a, b| a.id.cmp(&b.id));
        for group in &mut self.coupling_groups {
            group.members.sort();
            for edge in &mut group.evidence {
                edge.members.sort();
                edge.sites.sort_by(site_cmp);
            }
            group.evidence.sort_by(|a, b| {
                let ak = (format!("{:?}", a.kind), &a.members);
                let bk = (format!("{:?}", b.kind), &b.members);
                ak.cmp(&bk)
            });
        }
        if let Some(report) = &mut self.override_report {
            for entry in &mut report.entries {
                if let Some(failures) = &mut entry.failures {
                    failures.sort_by(guard_failure_cmp);
                }
            }
            report.entries.sort_by(|a, b| {
                (
                    format!("{:?}", a.scope),
                    &a.key,
                    format!("{:?}", a.requested),
                )
                    .cmp(&(
                        format!("{:?}", b.scope),
                        &b.key,
                        format!("{:?}", b.requested),
                    ))
            });
        }
        if let Some(materialization) = &mut self.materialization {
            materialization
                .marker_inventory
                .sort_by(|a, b| a.key.cmp(&b.key).then_with(|| a.kind.cmp(&b.kind)));
            materialization.demotions.sort_by(|a, b| a.key.cmp(&b.key));
        }
    }
}

fn canonicalize_facts(facts: &mut Facts) {
    for certificate in [
        &mut facts.phase_stationarity,
        &mut facts.atomic_eligibility,
        &mut facts.mutex_eligibility,
    ]
    .into_iter()
    .filter_map(Option::as_mut)
    {
        if let Certificate::Failed {
            codes, witnesses, ..
        } = certificate
        {
            codes.sort();
            witnesses.sort_by(witness_cmp);
        }
    }
    if let Some(localization) = &mut facts.localization {
        localization
            .blockers
            .sort_by(|a, b| witness_cmp(&a.witness, &b.witness).then_with(|| a.code.cmp(&b.code)));
    }
}

fn site_cmp(a: &Site, b: &Site) -> Ordering {
    (&a.file, a.line, a.col, &a.function).cmp(&(&b.file, b.line, b.col, &b.function))
}

fn witness_cmp(a: &Witness, b: &Witness) -> Ordering {
    (
        &a.kind,
        a.site.as_ref().map(|site| &site.file),
        a.site.as_ref().map(|site| site.line),
        a.site.as_ref().and_then(|site| site.col),
        &a.symbol,
        &a.note,
    )
        .cmp(&(
            &b.kind,
            b.site.as_ref().map(|site| &site.file),
            b.site.as_ref().map(|site| site.line),
            b.site.as_ref().and_then(|site| site.col),
            &b.symbol,
            &b.note,
        ))
}

fn guard_failure_cmp(a: &GuardFailure, b: &GuardFailure) -> Ordering {
    a.member
        .cmp(&b.member)
        .then_with(|| a.guard.cmp(&b.guard))
        .then_with(|| witness_cmp(&a.witness, &b.witness))
}

pub fn read_manifest(path: &Path) -> Result<Manifest, Error> {
    let manifest: Manifest = serde_json::from_slice(&fs::read(path)?)?;
    manifest.validate()?;
    Ok(manifest)
}

pub fn to_canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn write_canonical_json<T: Serialize>(path: &Path, value: &T) -> Result<(), Error> {
    fs::write(path, to_canonical_json(value)?)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerKind<'a> {
    Publish,
    Disposition(&'a str),
}

pub fn marker_name(kind: MarkerKind<'_>, raw_id: &str) -> String {
    let kind = match kind {
        MarkerKind::Publish => "publish".to_owned(),
        MarkerKind::Disposition(strategy) => format!("disposition_{strategy}"),
    };
    let mangled: String = raw_id
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() {
                char::from(b)
            } else {
                '_'
            }
        })
        .collect();
    format!(
        "pangs_{kind}__{mangled}__{:08x}",
        fnv1a32(raw_id.as_bytes())
    )
}

pub fn check_marker_collisions<'a>(
    entries: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<(), Error> {
    let mut seen = BTreeMap::<&str, &str>::new();
    for (id, marker) in entries {
        if let Some(first) = seen.insert(marker, id) {
            if first != id {
                return Err(Error::MarkerCollision {
                    marker: marker.to_owned(),
                    first: first.to_owned(),
                    second: id.to_owned(),
                });
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedMarker {
    pub key: Key,
    pub kind: String,
    pub marker: String,
    pub group: Option<String>,
}

pub fn expected_markers(manifest: &Manifest) -> Result<Vec<ExpectedMarker>, Error> {
    let mut expected = Vec::new();
    for global in &manifest.globals {
        let Some(disposition) = &global.disposition else {
            continue;
        };
        let (kind, raw_id, group) = match disposition.chosen {
            Strategy::OnceLock => {
                let group = global.facts.coupling_group.clone();
                let raw_id = group.clone().unwrap_or_else(|| global.key.to_string());
                ("publish".to_owned(), raw_id, group)
            }
            Strategy::Immutable | Strategy::Atomic | Strategy::Mutex => (
                format!("disposition_{}", disposition.chosen.as_str()),
                global.key.to_string(),
                None,
            ),
            Strategy::Localize | Strategy::Unhandled => continue,
        };
        let marker_kind = if kind == "publish" {
            MarkerKind::Publish
        } else {
            MarkerKind::Disposition(disposition.chosen.as_str())
        };
        expected.push(ExpectedMarker {
            key: global.key.clone(),
            kind,
            marker: marker_name(marker_kind, &raw_id),
            group,
        });
    }
    expected.sort_by(|a, b| a.key.cmp(&b.key));
    check_marker_collisions(
        expected
            .iter()
            .map(|entry| {
                (
                    entry.group.clone().unwrap_or_else(|| entry.key.to_string()),
                    entry.marker.clone(),
                )
            })
            .collect::<Vec<_>>()
            .iter()
            .map(|(key, marker)| (key.as_str(), marker.as_str())),
    )?;
    Ok(expected)
}

#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("marker inventory differs from the disposition-derived inventory")]
    InventoryMismatch,
    #[error("expected marker is missing from translated input: {0}")]
    MissingMarker(String),
    #[error("orphan marker symbol in translated input: {0}")]
    OrphanMarker(String),
    #[error(transparent)]
    Codec(#[from] Error),
}

pub fn validate_marker_inventory<'a>(
    manifest: &Manifest,
    observed_marker_symbols: impl IntoIterator<Item = &'a str>,
) -> Result<(), InventoryError> {
    let expected = expected_markers(manifest)?;
    let actual = manifest
        .materialization
        .as_ref()
        .map(|value| {
            let mut rows = value
                .marker_inventory
                .iter()
                .map(|row| ExpectedMarker {
                    key: row.key.clone(),
                    kind: row.kind.clone(),
                    marker: row.marker.clone(),
                    group: row.group.clone(),
                })
                .collect::<Vec<_>>();
            rows.sort_by(|a, b| a.key.cmp(&b.key));
            rows
        })
        .unwrap_or_default();
    if actual != expected {
        return Err(InventoryError::InventoryMismatch);
    }
    let symbols = expected
        .iter()
        .map(|entry| entry.marker.as_str())
        .collect::<BTreeSet<_>>();
    let observed = observed_marker_symbols.into_iter().collect::<BTreeSet<_>>();
    for symbol in &symbols {
        if !observed.contains(symbol) {
            return Err(InventoryError::MissingMarker((*symbol).to_owned()));
        }
    }
    for symbol in observed {
        if symbol.starts_with("pangs_") && !symbols.contains(symbol) {
            return Err(InventoryError::OrphanMarker(symbol.to_owned()));
        }
    }
    Ok(())
}

pub fn marker_artifacts(manifest: &Manifest) -> Result<(String, String), Error> {
    let markers = expected_markers(manifest)?;
    let symbols = markers
        .iter()
        .map(|entry| entry.marker.as_str())
        .collect::<BTreeSet<_>>();
    let mut header = String::from(
        "#ifndef PANGS_MARKERS_H\n#define PANGS_MARKERS_H\n\n#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n",
    );
    let mut source = String::from("#include \"pangs_markers.h\"\n\n");
    for symbol in symbols {
        header.push_str(&format!("void {symbol}(void);\n"));
        source.push_str(&format!("void {symbol}(void) {{}}\n"));
    }
    header.push_str("\n#ifdef __cplusplus\n}\n#endif\n\n#endif\n");
    Ok((header, source))
}

fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5u32;
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AuditScope {
    Run {
        #[serde(flatten)]
        extra: Extra,
    },
    Global {
        key: Key,
        #[serde(flatten)]
        extra: Extra,
    },
    Group {
        key: String,
        #[serde(flatten)]
        extra: Extra,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditSource {
    Analysis,
    Override,
    EntrySpine,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: String,
    pub kind: String,
    pub scope: AuditScope,
    pub source: AuditSource,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<Witness>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failures: Option<Vec<GuardFailure>>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl AuditRecord {
    pub fn regenerate_id(&mut self) -> Result<(), Error> {
        let mut value = serde_json::to_value(&*self)?;
        value
            .as_object_mut()
            .expect("audit record is an object")
            .remove("id");
        let digest = Sha256::digest(serde_json::to_vec(&value)?);
        self.id = format!("ar-{}", hex_prefix(&digest, 16));
        Ok(())
    }
}

pub fn canonicalize_audit(records: &mut Vec<AuditRecord>) -> Result<(), Error> {
    for record in records.iter_mut() {
        if let Some(failures) = &mut record.failures {
            failures.sort_by(guard_failure_cmp);
        }
        record.regenerate_id()?;
    }
    records.sort_by(|a, b| a.id.cmp(&b.id));
    let mut ids = BTreeSet::new();
    for record in records {
        if !ids.insert(record.id.clone()) {
            return Err(Error::AuditIdCollision(record.id.clone()));
        }
    }
    Ok(())
}

fn hex_prefix(bytes: &[u8], count: usize) -> String {
    bytes
        .iter()
        .take(count)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_round_trip_and_validation() {
        for raw in [
            "src/commands.c::cmd_table",
            "vendor/a:b.c::name.$1",
            "one.c::static.42",
            "globally_unique_static.42",
        ] {
            let parsed = Key::parse(raw).unwrap();
            assert_eq!(parsed.to_string(), raw);
        }
        for raw in [
            "/src/a.c::g",
            "./src/a.c::g",
            "a/../b.c::g",
            "a.c::bad-name",
            "bad-name",
        ] {
            assert!(Key::parse(raw).is_err(), "accepted {raw}");
        }
    }

    #[test]
    fn marker_codec_is_stable_and_collision_checked() {
        let key = "src/commands.c::cmd_table";
        assert_eq!(
            marker_name(MarkerKind::Publish, key),
            "pangs_publish__src_commands_c__cmd_table__55efbf8e"
        );
        let err = check_marker_collisions([("a", "same"), ("b", "same")]).unwrap_err();
        assert!(matches!(err, Error::MarkerCollision { .. }));
    }

    #[test]
    fn canonical_json_has_trailing_newline_and_sorted_unknown_fields() {
        let mut extra = Extra::new();
        extra.insert("z_future".into(), Value::Bool(true));
        extra.insert("a_future".into(), Value::Bool(false));
        let witness = Witness {
            kind: "write-site".into(),
            site: None,
            symbol: None,
            note: None,
            extra,
        };
        let text = String::from_utf8(to_canonical_json(&witness).unwrap()).unwrap();
        assert!(text.ends_with('\n'));
        assert!(text.find("a_future").unwrap() < text.find("z_future").unwrap());
        let reparsed: Witness = serde_json::from_str(&text).unwrap();
        assert_eq!(to_canonical_json(&reparsed).unwrap(), text.as_bytes());
    }

    #[test]
    fn audit_id_covers_evidence_and_is_128_bits() {
        let mut record = AuditRecord {
            id: String::new(),
            kind: "accepted-risk".into(),
            scope: AuditScope::Run {
                extra: Extra::new(),
            },
            source: AuditSource::Override,
            text: "risk".into(),
            witness: None,
            failures: None,
            extra: Extra::new(),
        };
        record.regenerate_id().unwrap();
        let first = record.id.clone();
        assert_eq!(first.len(), 35);
        record.text = "different".into();
        record.regenerate_id().unwrap();
        assert_ne!(record.id, first);
    }

    #[test]
    fn literal_group_support_discriminant_is_enforced() {
        let bad = serde_json::json!({
            "supported": false,
            "publication_function": "src/a.c::f",
            "common_interval": {
                "earliest": {"file": "src/a.c", "line": 1},
                "latest": {"file": "src/a.c", "line": 2}
            },
            "common_p": {"file": "src/a.c", "line": 2}
        });
        assert!(serde_json::from_value::<OnceLockGroupSupport>(bad).is_err());
    }

    #[test]
    fn shipped_schemas_compile() {
        for text in [
            include_str!("../../../schemas/disposition-manifest.schema.json"),
            include_str!("../../../schemas/disposition-audit.schema.json"),
        ] {
            let schema: Value = serde_json::from_str(text).unwrap();
            jsonschema::JSONSchema::compile(&schema).unwrap();
        }
    }
}
