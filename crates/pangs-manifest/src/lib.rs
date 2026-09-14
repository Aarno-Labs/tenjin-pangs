use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::ops::Deref;
use std::path::Path;
use std::sync::Arc;

use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const SCHEMA_VERSION: u32 = 8;
pub type Extra = BTreeMap<String, Value>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid symbol key: {0}")]
    InvalidKey(String),
    #[error("unsupported disposition manifest schema version {found} (required {supported})")]
    UnsupportedSchema { found: u32, supported: u32 },
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
    // OnceLock and Mutex remain valid strategies, facts, and explicit cascade choices, but are
    // temporarily omitted from the automatic policy while their rewrite paths are disabled.
    pub const DEFAULT_APPLICATION: [Self; 3] = [Self::Immutable, Self::Atomic, Self::Localize];
    pub const DEFAULT_LIBRARY: [Self; 2] = [Self::Immutable, Self::Atomic];

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ViolationRelevance {
    AddressRelevant,
    AccessShapeRelevant,
    ValueOnly,
    Unrelated,
    Unresolved,
}

impl ViolationRelevance {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AddressRelevant => "address-relevant",
            Self::AccessShapeRelevant => "access-shape-relevant",
            Self::ValueOnly => "value-only",
            Self::Unrelated => "unrelated",
            Self::Unresolved => "unresolved",
        }
    }

    pub fn is_hard(self) -> bool {
        matches!(
            self,
            Self::AddressRelevant | Self::AccessShapeRelevant | Self::Unresolved
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ViolationRelevanceDiagnostic {
    pub classification: ViolationRelevance,
    pub finding_kind: String,
    #[serde(with = "violation_relevance_witness")]
    pub witness: Witness,
}

mod violation_relevance_witness {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::{Extra, Site, Witness};

    #[derive(Serialize)]
    struct CanonicalSite<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        col: Option<u32>,
        file: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        function: Option<&'a str>,
        line: u32,
        #[serde(flatten)]
        extra: &'a Extra,
    }

    impl<'a> From<&'a Site> for CanonicalSite<'a> {
        fn from(site: &'a Site) -> Self {
            Self {
                col: site.col,
                file: &site.file,
                function: site.function.as_deref(),
                line: site.line,
                extra: &site.extra,
            }
        }
    }

    #[derive(Serialize)]
    struct CanonicalWitness<'a> {
        kind: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        note: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        site: Option<CanonicalSite<'a>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        symbol: Option<&'a str>,
        #[serde(flatten)]
        extra: &'a Extra,
    }

    pub fn serialize<S>(witness: &Witness, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        CanonicalWitness {
            kind: &witness.kind,
            note: witness.note.as_deref(),
            site: witness.site.as_ref().map(CanonicalSite::from),
            symbol: witness.symbol.as_deref(),
            extra: &witness.extra,
        }
        .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Witness, D::Error>
    where
        D: Deserializer<'de>,
    {
        Witness::deserialize(deserializer)
    }
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
    pub blocker_count: usize,
    pub blocker_samples: Vec<LocalizationBlocker>,
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
    pub atomic_declaration: EvidencedBool,
    pub phase_stationarity: Option<Certificate>,
    pub mutex_eligibility: Option<Certificate>,
    pub coupling_group: Option<String>,
    pub localization: Option<Localization>,
    #[serde(default)]
    pub violation_relevance: Vec<ViolationRelevanceDiagnostic>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl Facts {
    pub fn validate(&self) -> Result<(), Error> {
        self.written.validate("written", true)?;
        self.omega_escaped_address
            .validate("omega_escaped_address", true)?;
        self.violation_taint.validate("violation_taint", true)?;
        let has_hard_violation = self
            .violation_relevance
            .iter()
            .any(|diagnostic| diagnostic.classification.is_hard());
        if self.violation_taint.value != has_hard_violation {
            return Err(Error::InvalidInvariant(
                "violation_taint must equal the presence of a hard violation_relevance diagnostic"
                    .into(),
            ));
        }
        self.thread_visible.validate("thread_visible", true)?;
        self.signal_context_access
            .validate("signal_context_access", true)?;
        self.access_set_complete
            .validate("access_set_complete", false)?;
        self.atomic_declaration
            .validate("atomic_declaration", true)?;
        for (name, slot) in [
            ("phase_stationarity", &self.phase_stationarity),
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
            if blockers_expected != (localization.blocker_count > 0)
                || (localization.blocker_count > 0) != !localization.blocker_samples.is_empty()
                || localization.blocker_samples.len() > localization.blocker_count
            {
                return Err(Error::InvalidInvariant(
                    "localization blocker count and samples must be present exactly when blocked, and samples cannot exceed the count".into(),
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
    /// Compiler-generated storage objects that must be transformed together with this
    /// source-level global. Their analysis facts are conservatively folded into `facts`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub storage_members: Vec<StorageMember>,
    pub facts: Facts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disposition: Option<Disposition>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StorageMember {
    pub llvm_name: String,
    pub kind: String,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyntheticGlobal {
    pub llvm_name: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<Key>,
    pub witness: Witness,
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
    #[serde(default)]
    pub strength: EvidenceStrength,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceStrength {
    Hard,
    Suspected,
}

impl Default for EvidenceStrength {
    fn default() -> Self {
        Self::Hard
    }
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
    pub mutex: Option<Certificate>,
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
pub struct CouplingCandidate {
    pub id: String,
    pub members: Vec<Key>,
    pub evidence: Vec<EvidenceEdge>,
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

/// Copy-on-write guard-failure set shared by the override report and audit ledger.
#[derive(Debug, Clone, PartialEq)]
pub struct SharedGuardFailures(Arc<Vec<GuardFailure>>);

impl SharedGuardFailures {
    pub fn make_mut(&mut self) -> &mut Vec<GuardFailure> {
        Arc::make_mut(&mut self.0)
    }

    fn canonicalize(&mut self) {
        if !self
            .windows(2)
            .all(|pair| guard_failure_cmp(&pair[0], &pair[1]) != Ordering::Greater)
        {
            self.make_mut().sort_by(guard_failure_cmp);
        }
    }
}

impl From<Vec<GuardFailure>> for SharedGuardFailures {
    fn from(value: Vec<GuardFailure>) -> Self {
        Self(Arc::new(value))
    }
}

impl Deref for SharedGuardFailures {
    type Target = [GuardFailure];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl Serialize for SharedGuardFailures {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.as_slice().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SharedGuardFailures {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Vec::<GuardFailure>::deserialize(deserializer).map(Self::from)
    }
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
    pub failures: Option<SharedGuardFailures>,
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

/// Analysis-owned source rewrite recipe for one candidate context field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextRewriteField {
    pub global: Key,
    pub llvm_name: String,
    pub accessors: Vec<String>,
    pub functions: Vec<String>,
    pub rewrite_callsites: Vec<ContextRewriteCallsite>,
    pub blockers: Vec<ContextRewriteBlocker>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextRewriteCallsite {
    pub key: String,
    pub caller: String,
    pub callees: Vec<String>,
    pub unresolved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site: Option<Site>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextRewriteBlocker {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callsite: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initializer: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Policy-owned projection of the candidate recipes whose final disposition is `localize`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SelectedContextRewrite {
    pub fields: Vec<ContextRewriteField>,
    pub accessors: Vec<String>,
    pub functions: Vec<String>,
    pub rewrite_callsites: Vec<ContextRewriteCallsite>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextRewritePlan {
    pub id: String,
    pub fields: Vec<ContextRewriteField>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected: Option<SelectedContextRewrite>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub run: RunHeader,
    pub globals: Vec<GlobalRecord>,
    /// Analyzed storage objects that have no independent source-level disposition.
    #[serde(default)]
    pub synthetic_globals: Vec<SyntheticGlobal>,
    pub unkeyed_globals: Vec<UnkeyedGlobal>,
    pub coupling_groups: Vec<CouplingGroup>,
    pub context_rewrite: ContextRewritePlan,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coupling_candidates: Vec<CouplingCandidate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub override_report: Option<OverrideReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub materialization: Option<Materialization>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl Manifest {
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(Error::UnsupportedSchema {
                found: self.schema_version,
                supported: SCHEMA_VERSION,
            });
        }
        let mut global_keys = BTreeSet::new();
        let mut storage_members = BTreeMap::new();
        for global in &self.globals {
            if !global_keys.insert(global.key.clone()) {
                return Err(Error::InvalidInvariant(format!(
                    "duplicate global key {}",
                    global.key
                )));
            }
            for member in &global.storage_members {
                if storage_members
                    .insert(member.llvm_name.clone(), global.key.clone())
                    .is_some()
                {
                    return Err(Error::InvalidInvariant(format!(
                        "synthetic storage member {} has multiple owners",
                        member.llvm_name
                    )));
                }
            }
            global.facts.validate()?;
        }
        let disposition_count = self
            .globals
            .iter()
            .filter(|global| global.disposition.is_some())
            .count();
        if disposition_count != 0 && disposition_count != self.globals.len() {
            return Err(Error::InvalidInvariant(
                "dispositions must be absent or finalized for every global".into(),
            ));
        }
        let mut synthetic_names = BTreeSet::new();
        for synthetic in &self.synthetic_globals {
            if !synthetic_names.insert(synthetic.llvm_name.clone()) {
                return Err(Error::InvalidInvariant(format!(
                    "duplicate synthetic global {}",
                    synthetic.llvm_name
                )));
            }
            if let Some(owner) = &synthetic.owner {
                if !global_keys.contains(owner) {
                    return Err(Error::InvalidInvariant(format!(
                        "synthetic global {} names absent owner {owner}",
                        synthetic.llvm_name
                    )));
                }
                if storage_members.get(&synthetic.llvm_name) != Some(owner) {
                    return Err(Error::InvalidInvariant(format!(
                        "owned synthetic global {} is absent from the named owner's storage closure",
                        synthetic.llvm_name
                    )));
                }
            }
        }
        if let Some(name) = storage_members
            .keys()
            .find(|name| !synthetic_names.contains(*name))
        {
            return Err(Error::InvalidInvariant(format!(
                "storage member {name} has no synthetic-global record"
            )));
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
            if group
                .evidence
                .iter()
                .any(|edge| edge.strength != EvidenceStrength::Hard)
            {
                return Err(Error::InvalidInvariant(format!(
                    "hard coupling group {} contains suspected evidence",
                    group.id
                )));
            }
        }
        let mut candidate_ids = BTreeSet::new();
        for candidate in &self.coupling_candidates {
            if !candidate_ids.insert(&candidate.id) {
                return Err(Error::InvalidInvariant(format!(
                    "duplicate coupling candidate id {}",
                    candidate.id
                )));
            }
            if group_ids.iter().any(|id| *id == &candidate.id) {
                return Err(Error::InvalidInvariant(format!(
                    "coupling candidate id collides with hard group {}",
                    candidate.id
                )));
            }
            for member in &candidate.members {
                if !global_keys.contains(member) {
                    return Err(Error::InvalidInvariant(format!(
                        "coupling candidate {} names absent member {member}",
                        candidate.id
                    )));
                }
            }
            if candidate
                .evidence
                .iter()
                .any(|edge| edge.strength != EvidenceStrength::Suspected)
            {
                return Err(Error::InvalidInvariant(format!(
                    "coupling candidate {} contains hard evidence",
                    candidate.id
                )));
            }
        }
        let mut rewrite_globals = BTreeSet::new();
        for field in &self.context_rewrite.fields {
            if !global_keys.contains(&field.global) {
                return Err(Error::InvalidInvariant(format!(
                    "context rewrite names absent global {}",
                    field.global
                )));
            }
            if !rewrite_globals.insert(field.global.clone()) {
                return Err(Error::InvalidInvariant(format!(
                    "duplicate context rewrite field {}",
                    field.global
                )));
            }
        }
        if let Some(selected) = &self.context_rewrite.selected {
            let selected_globals = selected
                .fields
                .iter()
                .map(|field| field.global.clone())
                .collect::<BTreeSet<_>>();
            let chosen_globals = self
                .globals
                .iter()
                .filter(|global| {
                    global
                        .disposition
                        .as_ref()
                        .is_some_and(|disposition| disposition.chosen == Strategy::Localize)
                })
                .map(|global| global.key.clone())
                .collect::<BTreeSet<_>>();
            if selected_globals != chosen_globals {
                return Err(Error::InvalidInvariant(
                    "selected context rewrite fields must exactly match localize dispositions"
                        .into(),
                ));
            }
            if selected_globals
                .iter()
                .any(|global| !rewrite_globals.contains(global))
            {
                return Err(Error::InvalidInvariant(
                    "selected context rewrite field has no analysis recipe".into(),
                ));
            }
        } else if self.run.dispose.is_some() {
            return Err(Error::InvalidInvariant(
                "finalized dispositions require a selected context rewrite".into(),
            ));
        }
        Ok(())
    }

    pub fn canonicalize(&mut self) {
        self.globals.sort_by(|a, b| a.key.cmp(&b.key));
        for global in &mut self.globals {
            global
                .storage_members
                .sort_by(|a, b| a.llvm_name.cmp(&b.llvm_name));
            canonicalize_facts(&mut global.facts);
        }
        self.synthetic_globals
            .sort_by(|a, b| a.llvm_name.cmp(&b.llvm_name));
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
        self.coupling_candidates.sort_by(|a, b| a.id.cmp(&b.id));
        for candidate in &mut self.coupling_candidates {
            candidate.members.sort();
            for edge in &mut candidate.evidence {
                edge.members.sort();
                edge.sites.sort_by(site_cmp);
            }
            candidate.evidence.sort_by(|a, b| {
                let ak = (format!("{:?}", a.kind), &a.members);
                let bk = (format!("{:?}", b.kind), &b.members);
                ak.cmp(&bk)
            });
        }
        canonicalize_context_rewrite(&mut self.context_rewrite);
        if let Some(report) = &mut self.override_report {
            for entry in &mut report.entries {
                if let Some(failures) = &mut entry.failures {
                    failures.canonicalize();
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

fn canonicalize_context_rewrite(plan: &mut ContextRewritePlan) {
    canonicalize_context_fields(&mut plan.fields);
    if let Some(selected) = &mut plan.selected {
        canonicalize_context_fields(&mut selected.fields);
        selected.accessors.sort();
        selected.accessors.dedup();
        selected.functions.sort();
        selected.functions.dedup();
        canonicalize_context_callsites(&mut selected.rewrite_callsites);
    }
}

fn canonicalize_context_fields(fields: &mut Vec<ContextRewriteField>) {
    for field in fields.iter_mut() {
        field.accessors.sort();
        field.accessors.dedup();
        field.functions.sort();
        field.functions.dedup();
        canonicalize_context_callsites(&mut field.rewrite_callsites);
        field.blockers.sort_by(|left, right| {
            (
                &left.kind,
                &left.function,
                &left.callsite,
                &left.initializer,
            )
                .cmp(&(
                    &right.kind,
                    &right.function,
                    &right.callsite,
                    &right.initializer,
                ))
        });
        field.blockers.dedup_by(|left, right| {
            (
                &left.kind,
                &left.function,
                &left.callsite,
                &left.initializer,
            ) == (
                &right.kind,
                &right.function,
                &right.callsite,
                &right.initializer,
            )
        });
    }
    fields.sort_by(|left, right| left.global.cmp(&right.global));
}

fn canonicalize_context_callsites(callsites: &mut Vec<ContextRewriteCallsite>) {
    for callsite in callsites.iter_mut() {
        callsite.callees.sort();
        callsite.callees.dedup();
    }
    callsites.sort_by(|left, right| left.key.cmp(&right.key));
    callsites.dedup_by(|left, right| left.key == right.key);
}

fn canonicalize_facts(facts: &mut Facts) {
    for certificate in [&mut facts.phase_stationarity, &mut facts.mutex_eligibility]
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
            .blocker_samples
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
                let group = manifest
                    .coupling_groups
                    .iter()
                    .find(|group| {
                        group.group_disposition == Some(Strategy::OnceLock)
                            && group.members.contains(&global.key)
                    })
                    .map(|group| group.id.clone());
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
    pub failures: Option<SharedGuardFailures>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl AuditRecord {
    pub fn regenerate_id(&mut self) -> Result<(), Error> {
        let mut hasher = Sha256::new();
        serde_json::to_writer(DigestWriter(&mut hasher), &AuditRecordContent(self))?;
        let digest = hasher.finalize();
        self.id = format!("ar-{}", hex_prefix(&digest, 16));
        Ok(())
    }
}

/// Borrowed view of an audit record's ID-covered content. Field names are sorted exactly as
/// `serde_json::Value` object keys were, preserving existing IDs without cloning a second tree.
struct AuditRecordContent<'a>(&'a AuditRecord);

enum AuditField<'a> {
    Kind(&'a str),
    Scope(&'a AuditScope),
    Source(AuditSource),
    Text(&'a str),
    Witness(&'a Witness),
    Failures(&'a [GuardFailure]),
    Extra(&'a Value),
}

impl Serialize for AuditField<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Kind(value) | Self::Text(value) => value.serialize(serializer),
            Self::Scope(value) => AuditScopeContent(value).serialize(serializer),
            Self::Source(value) => value.serialize(serializer),
            Self::Witness(value) => AuditWitnessContent(value).serialize(serializer),
            Self::Failures(value) => AuditFailuresContent(value).serialize(serializer),
            Self::Extra(value) => value.serialize(serializer),
        }
    }
}

struct AuditScopeContent<'a>(&'a AuditScope);

enum AuditScopeField<'a> {
    String(&'a str),
    Key(&'a Key),
    Extra(&'a Value),
}

impl Serialize for AuditScopeField<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::String(value) => value.serialize(serializer),
            Self::Key(value) => value.serialize(serializer),
            Self::Extra(value) => value.serialize(serializer),
        }
    }
}

impl Serialize for AuditScopeContent<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let (kind, key, extra) = match self.0 {
            AuditScope::Run { extra } => ("run", None, extra),
            AuditScope::Global { key, extra } => ("global", Some(AuditScopeField::Key(key)), extra),
            AuditScope::Group { key, extra } => {
                ("group", Some(AuditScopeField::String(key)), extra)
            }
        };
        let mut fields = extra
            .iter()
            .map(|(name, value)| (name.as_str(), AuditScopeField::Extra(value)))
            .collect::<Vec<_>>();
        if !extra.contains_key("kind") {
            fields.push(("kind", AuditScopeField::String(kind)));
        }
        if !extra.contains_key("key") {
            if let Some(key) = key {
                fields.push(("key", key));
            }
        }
        fields.sort_by(|left, right| left.0.cmp(right.0));
        let mut map = serializer.serialize_map(Some(fields.len()))?;
        for (name, value) in fields {
            map.serialize_entry(name, &value)?;
        }
        map.end()
    }
}

struct AuditWitnessContent<'a>(&'a Witness);

enum AuditWitnessField<'a> {
    String(&'a str),
    Site(&'a Site),
    Extra(&'a Value),
}

impl Serialize for AuditWitnessField<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::String(value) => value.serialize(serializer),
            Self::Site(value) => AuditSiteContent(value).serialize(serializer),
            Self::Extra(value) => value.serialize(serializer),
        }
    }
}

impl Serialize for AuditWitnessContent<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let witness = self.0;
        let mut fields = witness
            .extra
            .iter()
            .map(|(name, value)| (name.as_str(), AuditWitnessField::Extra(value)))
            .collect::<Vec<_>>();
        if !witness.extra.contains_key("kind") {
            fields.push(("kind", AuditWitnessField::String(&witness.kind)));
        }
        if !witness.extra.contains_key("note") {
            if let Some(note) = witness.note.as_deref() {
                fields.push(("note", AuditWitnessField::String(note)));
            }
        }
        if !witness.extra.contains_key("site") {
            if let Some(site) = &witness.site {
                fields.push(("site", AuditWitnessField::Site(site)));
            }
        }
        if !witness.extra.contains_key("symbol") {
            if let Some(symbol) = witness.symbol.as_deref() {
                fields.push(("symbol", AuditWitnessField::String(symbol)));
            }
        }
        fields.sort_by(|left, right| left.0.cmp(right.0));
        let mut map = serializer.serialize_map(Some(fields.len()))?;
        for (name, value) in fields {
            map.serialize_entry(name, &value)?;
        }
        map.end()
    }
}

struct AuditSiteContent<'a>(&'a Site);

enum AuditSiteField<'a> {
    String(&'a str),
    U32(u32),
    Extra(&'a Value),
}

impl Serialize for AuditSiteField<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::String(value) => value.serialize(serializer),
            Self::U32(value) => value.serialize(serializer),
            Self::Extra(value) => value.serialize(serializer),
        }
    }
}

impl Serialize for AuditSiteContent<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let site = self.0;
        let mut fields = site
            .extra
            .iter()
            .map(|(name, value)| (name.as_str(), AuditSiteField::Extra(value)))
            .collect::<Vec<_>>();
        if !site.extra.contains_key("col") {
            if let Some(col) = site.col {
                fields.push(("col", AuditSiteField::U32(col)));
            }
        }
        if !site.extra.contains_key("file") {
            fields.push(("file", AuditSiteField::String(&site.file)));
        }
        if !site.extra.contains_key("function") {
            if let Some(function) = site.function.as_deref() {
                fields.push(("function", AuditSiteField::String(function)));
            }
        }
        if !site.extra.contains_key("line") {
            fields.push(("line", AuditSiteField::U32(site.line)));
        }
        fields.sort_by(|left, right| left.0.cmp(right.0));
        let mut map = serializer.serialize_map(Some(fields.len()))?;
        for (name, value) in fields {
            map.serialize_entry(name, &value)?;
        }
        map.end()
    }
}

struct AuditFailuresContent<'a>(&'a [GuardFailure]);

impl Serialize for AuditFailuresContent<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for failure in self.0 {
            sequence.serialize_element(&AuditGuardFailureContent(failure))?;
        }
        sequence.end()
    }
}

struct AuditGuardFailureContent<'a>(&'a GuardFailure);

enum AuditGuardFailureField<'a> {
    String(&'a str),
    Key(&'a Key),
    Witness(&'a Witness),
    Extra(&'a Value),
}

impl Serialize for AuditGuardFailureField<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::String(value) => value.serialize(serializer),
            Self::Key(value) => value.serialize(serializer),
            Self::Witness(value) => AuditWitnessContent(value).serialize(serializer),
            Self::Extra(value) => value.serialize(serializer),
        }
    }
}

impl Serialize for AuditGuardFailureContent<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let failure = self.0;
        let mut fields = failure
            .extra
            .iter()
            .map(|(name, value)| (name.as_str(), AuditGuardFailureField::Extra(value)))
            .collect::<Vec<_>>();
        if !failure.extra.contains_key("guard") {
            fields.push(("guard", AuditGuardFailureField::String(&failure.guard)));
        }
        if !failure.extra.contains_key("member") {
            fields.push(("member", AuditGuardFailureField::Key(&failure.member)));
        }
        if !failure.extra.contains_key("witness") {
            fields.push(("witness", AuditGuardFailureField::Witness(&failure.witness)));
        }
        fields.sort_by(|left, right| left.0.cmp(right.0));
        let mut map = serializer.serialize_map(Some(fields.len()))?;
        for (name, value) in fields {
            map.serialize_entry(name, &value)?;
        }
        map.end()
    }
}

impl Serialize for AuditRecordContent<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let record = self.0;
        let mut fields = Vec::with_capacity(6 + record.extra.len());
        fields.extend(
            record
                .extra
                .iter()
                .filter(|(key, _)| key.as_str() != "id")
                .map(|(key, value)| (key.as_str(), AuditField::Extra(value))),
        );
        // Flattened extras were serialized after the typed fields previously, so an extra with a
        // reserved name replaced that typed field when serde built the temporary JSON object.
        if !record.extra.contains_key("kind") {
            fields.push(("kind", AuditField::Kind(&record.kind)));
        }
        if !record.extra.contains_key("scope") {
            fields.push(("scope", AuditField::Scope(&record.scope)));
        }
        if !record.extra.contains_key("source") {
            fields.push(("source", AuditField::Source(record.source)));
        }
        if !record.extra.contains_key("text") {
            fields.push(("text", AuditField::Text(&record.text)));
        }
        if !record.extra.contains_key("witness") {
            if let Some(witness) = &record.witness {
                fields.push(("witness", AuditField::Witness(witness)));
            }
        }
        if !record.extra.contains_key("failures") {
            if let Some(failures) = &record.failures {
                fields.push(("failures", AuditField::Failures(failures)));
            }
        }
        fields.sort_by(|left, right| left.0.cmp(right.0));

        let mut map = serializer.serialize_map(Some(fields.len()))?;
        for (name, value) in fields {
            map.serialize_entry(name, &value)?;
        }
        map.end()
    }
}

struct DigestWriter<'a>(&'a mut Sha256);

impl Write for DigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn canonicalize_audit(records: &mut Vec<AuditRecord>) -> Result<(), Error> {
    for record in records.iter_mut() {
        if let Some(failures) = &mut record.failures {
            failures.canonicalize();
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
    fn typed_violation_diagnostic_preserves_legacy_json_order() {
        let diagnostic = ViolationRelevanceDiagnostic {
            classification: ViolationRelevance::Unrelated,
            finding_kind: "fnptr_ptrtoint".into(),
            witness: Witness {
                kind: "violation-unrelated".into(),
                site: Some(Site {
                    file: "src/a.c".into(),
                    line: 7,
                    col: Some(3),
                    function: Some("f".into()),
                    extra: Extra::new(),
                }),
                symbol: Some("g".into()),
                note: Some("fnptr_ptrtoint".into()),
                extra: Extra::new(),
            },
        };
        let text = serde_json::to_string(&diagnostic).unwrap();
        assert_eq!(
            text,
            r#"{"classification":"unrelated","finding_kind":"fnptr_ptrtoint","witness":{"kind":"violation-unrelated","note":"fnptr_ptrtoint","site":{"col":3,"file":"src/a.c","function":"f","line":7},"symbol":"g"}}"#
        );
        assert_eq!(
            serde_json::from_str::<ViolationRelevanceDiagnostic>(&text).unwrap(),
            diagnostic
        );
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
    fn borrowed_audit_id_serialization_matches_legacy_value_tree() {
        let witness = Witness {
            kind: "guard-failed".into(),
            site: Some(Site {
                file: "src/a.c".into(),
                line: 17,
                col: Some(9),
                function: Some("worker".into()),
                extra: BTreeMap::from([("address".into(), serde_json::json!("0x10"))]),
            }),
            symbol: Some("state".into()),
            note: Some("evidence".into()),
            extra: BTreeMap::from([("detail".into(), serde_json::json!({"z": 2, "a": 1}))]),
        };
        let mut record = AuditRecord {
            id: "ignored".into(),
            kind: "override-rejected".into(),
            scope: AuditScope::Global {
                key: Key::new("src/a.c", "state").unwrap(),
                extra: BTreeMap::from([("scope_detail".into(), serde_json::json!(true))]),
            },
            source: AuditSource::Override,
            text: "rejected".into(),
            witness: Some(witness.clone()),
            failures: Some(
                vec![GuardFailure {
                    member: Key::new("src/a.c", "state").unwrap(),
                    guard: "access-set-complete".into(),
                    witness,
                    extra: BTreeMap::from([("rank".into(), serde_json::json!(1))]),
                }]
                .into(),
            ),
            extra: BTreeMap::from([("analysis_stage".into(), serde_json::json!("andersen"))]),
        };
        let mut legacy = serde_json::to_value(&record).unwrap();
        legacy.as_object_mut().unwrap().remove("id");
        let digest = Sha256::digest(serde_json::to_vec(&legacy).unwrap());
        let expected = format!("ar-{}", hex_prefix(&digest, 16));

        record.regenerate_id().unwrap();
        assert_eq!(record.id, expected);
    }

    #[test]
    fn canonical_guard_failure_sets_remain_shared_across_fields() {
        let failure = GuardFailure {
            member: Key::new("src/a.c", "state").unwrap(),
            guard: "written".into(),
            witness: Witness {
                kind: "guard-failed".into(),
                site: None,
                symbol: Some("state".into()),
                note: None,
                extra: Extra::new(),
            },
            extra: Extra::new(),
        };
        let mut report_failures = SharedGuardFailures::from(vec![failure]);
        let audit_failures = report_failures.clone();

        report_failures.canonicalize();

        assert!(Arc::ptr_eq(&report_failures.0, &audit_failures.0));
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
