use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};
use jsonschema::JSONSchema;

mod cc2json;
mod knobs;
mod phase_stationarity;
pub use cc2json::{run_cc2json, Cc2jsonOpts};

use pangs_api::{
    AffectedGlobals, Analysis, BuildMode, CallEdge, Callee, Caller, ComponentInfo, FuncId,
    GlobalId, GlobalTarget, ModRef, Opts, RegistryApi, RegistryEntryOperand, RegistryKind,
    StationarityVerdict, StationarityWriter,
};
use pangs_manifest::{
    canonicalize_audit, AlwaysFalse, AlwaysTrue, AnalysisRun, AuditRecord, AuditScope, AuditSource,
    Certificate, CommonInterval, CouplingGroup, EvidenceEdge, EvidenceKind, EvidenceStrength,
    EvidencedBool, Extra, Facts, GlobalRecord as DispositionGlobal, GroupStrategySupport, Key,
    Linkage, Localization, LocalizationBlocker, LocalizationVerdict,
    Manifest as DispositionManifest, Meta, OnceLockGroupSupport, RunHeader, ScalarClass, Site,
    StorageMember, SyntheticGlobal, UnkeyedGlobal,
    ViolationRelevance as ManifestViolationRelevance, ViolationRelevanceDiagnostic, Witness,
    WordSizedScalar, SCHEMA_VERSION,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn export_analysis(
    analysis: &Analysis,
    opts: &Opts,
    input_path: &Path,
    outdir: &Path,
    validate: bool,
    pipeline_started: Instant,
) -> Result<()> {
    fs::create_dir_all(outdir).with_context(|| format!("create {}", outdir.display()))?;

    let mut files = Vec::new();
    let mut functions: Vec<_> = analysis.functions().iter().collect();
    functions.sort_by_key(|func| func.key.clone());
    write_jsonl(
        outdir.join("functions.jsonl"),
        functions.into_iter().map(FunctionRecord::from),
        &mut files,
    )?;
    let mut globals: Vec<_> = analysis.globals().iter().collect();
    globals.sort_by_key(|global| global.key.clone());
    write_jsonl(
        outdir.join("globals.jsonl"),
        globals.into_iter().map(GlobalRecord::from),
        &mut files,
    )?;
    write_jsonl(
        outdir.join("callgraph.jsonl"),
        analysis
            .call_edges()
            .iter()
            .map(|edge| CallEdgeRecord::from_edge(edge, analysis)),
        &mut files,
    )?;
    write_jsonl(
        outdir.join("modref.jsonl"),
        analysis
            .modrefs()
            .iter()
            .map(|mr| ModRefRecord::from_modref(mr, analysis)),
        &mut files,
    )?;
    write_jsonl(
        outdir.join("stationarity.jsonl"),
        analysis
            .stationarity_verdicts()
            .iter()
            .map(|verdict| StationarityRecord::from_verdict(verdict, analysis)),
        &mut files,
    )?;
    write_jsonl(
        outdir.join("audit.jsonl"),
        analysis.audit_findings().iter(),
        &mut files,
    )?;
    write_json(
        outdir.join("components.json"),
        &ComponentsRecord::from_analysis(analysis),
        &mut files,
    )?;
    let metrics = analysis.metrics().clone();
    write_json(outdir.join("metrics.json"), &metrics, &mut files)?;

    let manifest = Manifest {
        schema_version: 1,
        pangs_git: option_env!("VERGEN_GIT_SHA")
            .unwrap_or("unknown")
            .to_string(),
        llvm_version: "llvm-14-planned".to_string(),
        input_path: input_path.display().to_string(),
        input_sha256: sha256_file(input_path)?,
        opts,
        files,
        wall_ms: pipeline_started.elapsed().as_millis() as u64,
    };
    write_json(outdir.join("manifest.json"), &manifest, &mut Vec::new())?;

    if validate {
        validate_export_dir(outdir)?;
    }
    Ok(())
}

pub fn assemble_disposition_artifacts(
    analysis: &Analysis,
    module: &pangs_pir::Pir,
    opts: &Opts,
    input_path: &Path,
    repo_root: &Path,
    target: &pangs_pir::TargetInfo,
) -> Result<(DispositionManifest, Vec<AuditRecord>)> {
    let repo_root = fs::canonicalize(repo_root)
        .with_context(|| format!("resolve repo root {}", repo_root.display()))?;
    let disposition_started = Instant::now();
    let registry_started = Instant::now();
    let registry_facts = registry_access_facts(analysis, module);
    if std::env::var_os(knobs::ENV_DISPOSITION_TIMINGS).is_some() {
        eprintln!(
            "pangs disposition timing registry-facts={}ms",
            registry_started.elapsed().as_millis()
        );
    }
    let fact_indexes_started = Instant::now();
    let fact_rows = DispositionFactRows::new(analysis);
    if std::env::var_os(knobs::ENV_DISPOSITION_TIMINGS).is_some() {
        eprintln!(
            "pangs disposition timing fact-row-indexes={}ms",
            fact_indexes_started.elapsed().as_millis()
        );
    }
    let (entry_spine, phase_slots, mut phase_report) = phase_stationarity::certificate_slots(
        analysis,
        module,
        opts,
        &registry_facts.pseudo_read_callsites,
        &registry_facts.spawn_read_callsites,
        &registry_facts.escape_read_callsites,
        &registry_facts.thread_writers,
        &fact_rows.violation,
    );
    if std::env::var_os(knobs::ENV_DISPOSITION_TIMINGS).is_some() {
        eprintln!(
            "pangs disposition timing through-phase-certificates={}ms",
            disposition_started.elapsed().as_millis()
        );
    }
    let global_facts_started = Instant::now();
    let mut globals = Vec::new();
    let mut synthetic_globals = Vec::new();
    let compound_literal_owners = compound_literal_owners(analysis, module);
    let mut pending_storage_members = Vec::new();
    let mut unkeyed_globals = Vec::new();
    for (index, info) in analysis.globals().iter().enumerate() {
        if !info.mutable || !info.is_definition {
            continue;
        }
        let llvm_name = info.key.clone();
        let symbol = info.key.strip_prefix('@').unwrap_or(&info.key);
        let key = match info
            .file
            .as_deref()
            .map_or_else(|| Key::unqualified(symbol), |file| Key::new(file, symbol))
            .or_else(|_| Key::unqualified(symbol))
        {
            Ok(key) => key,
            Err(_) => {
                unkeyed_globals.push(UnkeyedGlobal {
                    llvm_name,
                    witness: Witness {
                        kind: "invalid-symbol-name".into(),
                        site: None,
                        symbol: None,
                        note: Some(info.key.clone()),
                        extra: Extra::new(),
                    },
                    extra: Extra::new(),
                });
                continue;
            }
        };
        let gid = GlobalId(index as u32);
        let omega_escaped = info.address_escaped;
        let omega_witness = omega_escaped
            .then(|| omega_escape_witness(analysis, &key, info, fact_rows.escape[index]));
        // `never_written` intentionally includes static-initializer stores for the legacy
        // analysis surface. Disposition immutability cares about writes after initialization;
        // external storage remains may-written even without an observed runtime store.
        let written = info.runtime_written || info.escape == pangs_api::EscapeStatus::External;
        let write_witness = written.then(|| {
            written_witness(
                analysis,
                info,
                omega_witness.as_ref(),
                fact_rows.written[index],
            )
        });
        let violation_witness = fact_rows.violation[index].clone();
        let violation_taint = violation_witness.is_some();
        let access_failure = access_set_failure(
            analysis,
            &info.key,
            omega_witness.as_ref(),
            opts.build_mode,
            info.exported,
            fact_rows.access_failure[index],
        );
        let localization = fact_rows.localization[index].clone();
        let record = DispositionGlobal {
            key,
            meta: Meta {
                linkage: match info.linkage {
                    pangs_pir::SymbolLinkage::Internal => Linkage::Internal,
                    pangs_pir::SymbolLinkage::External => Linkage::External,
                },
                type_spelling: info.type_spelling.clone(),
                size_bits: info.size_bits,
                align_bits: info.align_bits,
                llvm_name: info.key.clone(),
                file: info.file.clone(),
                line: info.line,
                extra: Extra::new(),
            },
            facts: Facts {
                written: evidenced(written, true, write_witness),
                omega_escaped_address: evidenced(omega_escaped, true, omega_witness.clone()),
                violation_taint: evidenced(violation_taint, true, violation_witness.clone()),
                thread_visible: evidenced(
                    registry_facts.thread_visible.contains_key(&gid),
                    true,
                    registry_facts.thread_visible.get(&gid).cloned(),
                ),
                signal_context_access: evidenced(
                    registry_facts.signal_context_access.contains_key(&gid),
                    true,
                    registry_facts.signal_context_access.get(&gid).cloned(),
                ),
                access_set_complete: evidenced(access_failure.is_none(), false, access_failure),
                word_sized_scalar: word_sized_scalar(info, target),
                phase_stationarity: phase_slots.get(&gid).cloned(),
                atomic_eligibility: None,
                mutex_eligibility: None,
                coupling_group: None,
                localization,
                violation_relevance: fact_rows.violation_diagnostics[index].clone(),
                extra: Extra::new(),
            },
            storage_members: Vec::new(),
            disposition: None,
            extra: Extra::new(),
        };
        if is_unnamed_compound_literal(info) {
            let owner = compound_literal_owners.get(&info.key).cloned().flatten();
            let witness = Witness {
                kind: "compiler-generated-backing-storage".into(),
                site: None,
                symbol: Some(info.key.clone()),
                note: Some(match &owner {
                    Some(owner) => format!(
                        "constant-initializer ownership is unique; facts roll up to {owner}"
                    ),
                    None => "no unique named constant-initializer owner".into(),
                }),
                extra: Extra::new(),
            };
            synthetic_globals.push(SyntheticGlobal {
                llvm_name: info.key.clone(),
                kind: "unnamed-compound-literal".into(),
                owner: owner.clone(),
                witness,
                extra: Extra::new(),
            });
            if let Some(owner) = owner {
                pending_storage_members.push((owner, record));
            }
        } else {
            globals.push(record);
        }
    }
    let global_by_key = globals
        .iter()
        .enumerate()
        .map(|(index, global)| (global.key.clone(), index))
        .collect::<BTreeMap<_, _>>();
    for (owner, member) in pending_storage_members {
        let Some(&owner_index) = global_by_key.get(&owner) else {
            anyhow::bail!("synthetic storage owner {owner} has no disposition subject");
        };
        fold_storage_member(&mut globals[owner_index], member);
    }
    // Keep deterministic construction independent of LLVM's global enumeration order.
    synthetic_globals.sort_by(|left, right| left.llvm_name.cmp(&right.llvm_name));
    for global in &mut globals {
        global
            .storage_members
            .sort_by(|left, right| left.llvm_name.cmp(&right.llvm_name));
    }
    if std::env::var_os(knobs::ENV_DISPOSITION_TIMINGS).is_some() {
        eprintln!(
            "pangs disposition timing global-fact-assembly={}ms keyed={} unkeyed={}",
            global_facts_started.elapsed().as_millis(),
            globals.len(),
            unkeyed_globals.len()
        );
    }

    let mut unique_keys = BTreeSet::new();
    for global in &globals {
        if !unique_keys.insert(global.key.clone()) {
            anyhow::bail!(
                "duplicate disposition global key {}; static-variable uniquification invariant violated",
                global.key
            );
        }
    }

    let coupling_started = Instant::now();
    let mut coupling_groups = assemble_coupling_groups(analysis, &mut globals);
    let atomic_started = Instant::now();
    let signal_flag_globals = assemble_atomic_eligibility(analysis, module, target, &mut globals);
    if std::env::var_os(knobs::ENV_DISPOSITION_TIMINGS).is_some() {
        eprintln!(
            "pangs disposition timing atomic-eligibility={}ms certified={}",
            atomic_started.elapsed().as_millis(),
            globals
                .iter()
                .filter(|global| global
                    .facts
                    .atomic_eligibility
                    .as_ref()
                    .is_some_and(Certificate::is_certified))
                .count()
        );
    }
    let mutex_started = Instant::now();
    let mutex_reachability = MutexReachability::new(analysis);
    assemble_mutex_eligibility(analysis, &mutex_reachability, &mut globals);
    assemble_group_mutex_support(
        analysis,
        &mutex_reachability,
        &globals,
        &mut coupling_groups,
    );
    if std::env::var_os(knobs::ENV_DISPOSITION_TIMINGS).is_some() {
        eprintln!(
            "pangs disposition timing mutex-eligibility={}ms certified={}",
            mutex_started.elapsed().as_millis(),
            globals
                .iter()
                .filter(|global| global
                    .facts
                    .mutex_eligibility
                    .as_ref()
                    .is_some_and(Certificate::is_certified))
                .count()
        );
    }
    if std::env::var_os(knobs::ENV_DISPOSITION_TIMINGS).is_some() {
        eprintln!(
            "pangs disposition timing coupling-groups={}ms groups={} evidence-edges={}",
            coupling_started.elapsed().as_millis(),
            coupling_groups.len(),
            coupling_groups
                .iter()
                .map(|group| group.evidence.len())
                .sum::<usize>()
        );
    }
    if let Some(report) = phase_report.as_object_mut() {
        let mut relevance_by_classification = BTreeMap::<&str, u64>::new();
        let mut relevance_by_finding_kind = BTreeMap::<&str, u64>::new();
        for diagnostic in fact_rows.violation_diagnostics.iter().flatten() {
            *relevance_by_classification
                .entry(diagnostic.classification.as_str())
                .or_default() += 1;
            *relevance_by_finding_kind
                .entry(diagnostic.finding_kind.as_str())
                .or_default() += 1;
        }
        report.insert(
            "violation_relevance".into(),
            serde_json::json!({
                "by_classification": relevance_by_classification,
                "by_finding_kind": relevance_by_finding_kind,
                "hard_globals": fact_rows.violation.iter().filter(|witness| witness.is_some()).count(),
            }),
        );
        let bounded_indirect = fact_rows
            .bounded_indirect
            .iter()
            .enumerate()
            .filter_map(|(index, row)| {
                row.map(|row| {
                    serde_json::json!({
                        "global": analysis.globals()[GlobalId(index as u32)].key,
                        "witness": function_witness(
                            analysis,
                            row.func,
                            "bounded-indirect-access",
                            row.witness.clone(),
                        ),
                    })
                })
            })
            .collect::<Vec<_>>();
        report.insert(
            "bounded_indirect_accesses".into(),
            serde_json::json!({
                "globals": bounded_indirect.len(),
                "witnesses": bounded_indirect,
            }),
        );
        let summaries = coupling_groups
            .iter()
            .map(|group| {
                serde_json::json!({
                    "id": group.id,
                    "members": group.members.len(),
                    "once_lock_supported": matches!(
                        group.strategy_support.once_lock.as_ref(),
                        Some(OnceLockGroupSupport::Supported { .. })
                    )
                })
            })
            .collect::<Vec<_>>();
        report.insert(
            "coupling_groups".into(),
            serde_json::json!({
                "count": coupling_groups.len(),
                "globals_grouped": coupling_groups.iter().map(|group| group.members.len()).sum::<usize>(),
                "once_lock_supported": coupling_groups.iter().filter(|group| matches!(group.strategy_support.once_lock.as_ref(), Some(OnceLockGroupSupport::Supported { .. }))).count(),
                "once_lock_evidence_edges": coupling_groups.iter().flat_map(|group| &group.evidence).filter(|edge| edge.kind == EvidenceKind::OncelockInterval).count(),
                "groups": summaries
            }),
        );
        report.insert(
            "atomic_eligibility".into(),
            serde_json::json!({
                "certified": globals.iter().filter(|global| global.facts.atomic_eligibility.as_ref().is_some_and(Certificate::is_certified)).count(),
                "failed": globals.iter().filter(|global| matches!(global.facts.atomic_eligibility, Some(Certificate::Failed { .. }))).count(),
                "not_word_sized": globals.iter().filter(|global| !global.facts.word_sized_scalar.value).count(),
                "access_incomplete": globals.iter().filter(|global| !global.facts.access_set_complete.value).count(),
                "violation_tainted": globals.iter().filter(|global| global.facts.violation_taint.value).count(),
            }),
        );
        report.insert(
            "mutex_eligibility".into(),
            serde_json::json!({
                "certified": globals.iter().filter(|global| global.facts.mutex_eligibility.as_ref().is_some_and(Certificate::is_certified)).count(),
                "failed": globals.iter().filter(|global| matches!(global.facts.mutex_eligibility, Some(Certificate::Failed { .. }))).count(),
                "access_incomplete": globals.iter().filter(|global| !global.facts.access_set_complete.value).count(),
                "signal_context_access": globals.iter().filter(|global| global.facts.signal_context_access.value).count(),
                "violation_tainted": globals.iter().filter(|global| global.facts.violation_taint.value).count(),
            }),
        );
    }
    let mut manifest = DispositionManifest {
        schema_version: SCHEMA_VERSION,
        run: RunHeader {
            analysis: AnalysisRun {
                pangs_git: option_env!("VERGEN_GIT_SHA")
                    .unwrap_or("unknown")
                    .to_string(),
                llvm_version: "14".into(),
                input_path: input_path.display().to_string(),
                input_sha256: sha256_file(input_path)?,
                opts: serde_json::to_value(opts)?,
                repo_root: repo_root.display().to_string(),
                target_triple: target.triple.clone(),
                data_layout: target.data_layout.clone(),
                supported_atomic_widths: target.supported_atomic_widths.clone(),
                entry_spine,
                extra: BTreeMap::from([("phase_stationarity_report".into(), phase_report)]),
            },
            dispose: None,
            extra: Extra::new(),
        },
        globals,
        synthetic_globals,
        unkeyed_globals,
        coupling_groups,
        coupling_candidates: Vec::new(),
        override_report: None,
        materialization: None,
        extra: Extra::new(),
    };
    manifest.canonicalize();
    manifest.validate()?;
    let mut ledger = vec![AuditRecord {
        id: String::new(),
        kind: "run-assumption".into(),
        scope: AuditScope::Run {
            extra: Extra::new(),
        },
        source: AuditSource::Analysis,
        text: "global static-variable uniquification runs before PANGS analysis; bare manifest keys are globally unique".into(),
        witness: None,
        failures: None,
        extra: Extra::new(),
    }];
    if !signal_flag_globals.is_empty() {
        ledger.push(AuditRecord {
            id: String::new(),
            kind: "signal-flag-assumptions".into(),
            scope: AuditScope::Run {
                extra: Extra::new(),
            },
            source: AuditSource::Analysis,
            text: "Certified volatile sig_atomic_t globals are treated as notification flags and lowered to x86-64 i32 SeqCst atomics. The transformation assumes access count is not semantically load-bearing, that the flag is not part of a cross-object volatile protocol split across functions, and that the tested Rust backend emits inline operations without unbounded loop elision.".into(),
            witness: None,
            failures: None,
            extra: BTreeMap::from([(
                "context".into(),
                serde_json::json!({
                    "arch": "x86_64",
                    "width": 32,
                    "ordering": "seq_cst",
                    "globals": signal_flag_globals.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "regression": "tests/codegen/signal_flag_x86_64_i32",
                }),
            )]),
        });
    }
    canonicalize_audit(&mut ledger)?;
    Ok((manifest, ledger))
}

fn is_unnamed_compound_literal(info: &pangs_api::GlobalInfo) -> bool {
    info.synthetic_kind.as_deref() == Some("unnamed-compound-literal")
}

fn disposition_key(info: &pangs_api::GlobalInfo) -> Option<Key> {
    let symbol = info.key.strip_prefix('@').unwrap_or(&info.key);
    info.file
        .as_deref()
        .map_or_else(|| Key::unqualified(symbol), |file| Key::new(file, symbol))
        .or_else(|_| Key::unqualified(symbol))
        .ok()
}

/// Finds source-level globals that uniquely own compiler-generated compound-literal storage.
///
/// LLVM names initializer references without a leading `@`; analysis keys may retain it, so
/// identity is normalized only for this PIR-to-analysis join. A multiply referenced literal is
/// deliberately left ownerless: choosing either source global would hide a shared-storage
/// obligation.
fn compound_literal_owners(
    analysis: &Analysis,
    module: &pangs_pir::Pir,
) -> BTreeMap<String, Option<Key>> {
    let infos = analysis
        .globals()
        .iter()
        .map(|info| {
            (
                info.key.strip_prefix('@').unwrap_or(&info.key).to_owned(),
                info,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let synthetic_names = infos
        .iter()
        .filter_map(|(name, info)| is_unnamed_compound_literal(info).then_some(name.clone()))
        .collect::<BTreeSet<_>>();
    let mut owners = synthetic_names
        .iter()
        .map(|name| (name.clone(), BTreeSet::<Key>::new()))
        .collect::<BTreeMap<_, _>>();
    let initializer_refs = module
        .globals
        .iter()
        .map(|global| {
            (
                global
                    .key
                    .strip_prefix('@')
                    .unwrap_or(&global.key)
                    .to_owned(),
                global
                    .init_refs
                    .iter()
                    .map(|referenced| {
                        referenced
                            .strip_prefix('@')
                            .unwrap_or(referenced)
                            .to_owned()
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    for initializer in &module.globals {
        let initializer_name = initializer
            .key
            .strip_prefix('@')
            .unwrap_or(&initializer.key);
        let Some(info) = infos.get(initializer_name).copied() else {
            continue;
        };
        if is_unnamed_compound_literal(info) || !info.mutable || !info.is_definition {
            continue;
        }
        let Some(owner) = disposition_key(info) else {
            continue;
        };
        let mut pending = initializer_refs
            .get(initializer_name)
            .into_iter()
            .flatten()
            .cloned()
            .collect::<Vec<_>>();
        let mut seen = BTreeSet::new();
        while let Some(referenced) = pending.pop() {
            if synthetic_names.contains(&referenced) && seen.insert(referenced.clone()) {
                owners
                    .get_mut(&referenced)
                    .expect("synthetic owner table is complete")
                    .insert(owner.clone());
                pending.extend(
                    initializer_refs
                        .get(&referenced)
                        .into_iter()
                        .flatten()
                        .cloned(),
                );
            }
        }
    }

    owners
        .into_iter()
        .map(|(name, candidates)| {
            let owner = (candidates.len() == 1)
                .then(|| candidates.into_iter().next())
                .flatten();
            let analysis_name = infos
                .get(&name)
                .expect("synthetic analysis global exists")
                .key
                .clone();
            (analysis_name, owner)
        })
        .collect()
}

fn fold_storage_member(owner: &mut DispositionGlobal, member: DispositionGlobal) {
    owner.storage_members.push(StorageMember {
        llvm_name: member.meta.llvm_name.clone(),
        kind: "unnamed-compound-literal".into(),
        extra: Extra::new(),
    });

    fold_or_fact(&mut owner.facts.written, member.facts.written);
    fold_or_fact(
        &mut owner.facts.omega_escaped_address,
        member.facts.omega_escaped_address,
    );
    fold_or_fact(
        &mut owner.facts.violation_taint,
        member.facts.violation_taint,
    );
    fold_or_fact(&mut owner.facts.thread_visible, member.facts.thread_visible);
    fold_or_fact(
        &mut owner.facts.signal_context_access,
        member.facts.signal_context_access,
    );
    fold_and_fact(
        &mut owner.facts.access_set_complete,
        member.facts.access_set_complete,
    );
    owner.facts.phase_stationarity = fold_certificate(
        owner.facts.phase_stationarity.take(),
        member.facts.phase_stationarity,
    );
    owner.facts.localization =
        fold_localization(owner.facts.localization.take(), member.facts.localization);
    owner
        .facts
        .violation_relevance
        .extend(member.facts.violation_relevance);
}

fn fold_or_fact(owner: &mut EvidencedBool, member: EvidencedBool) {
    if !owner.value && member.value {
        *owner = member;
    }
}

fn fold_and_fact(owner: &mut EvidencedBool, member: EvidencedBool) {
    if owner.value && !member.value {
        *owner = member;
    }
}

fn fold_certificate(
    owner: Option<Certificate>,
    member: Option<Certificate>,
) -> Option<Certificate> {
    match (owner, member) {
        (Some(owner @ Certificate::Failed { .. }), _) => Some(owner),
        (_, Some(member @ Certificate::Failed { .. })) => Some(member),
        (
            Some(owner @ Certificate::Certified { .. }),
            Some(member @ Certificate::Certified { .. }),
        ) if owner == member => Some(owner),
        (Some(Certificate::Certified { .. }), Some(Certificate::Certified { .. })) => {
            Some(Certificate::Failed {
                codes: vec!["storage-closure-phase-mismatch".into()],
                witnesses: vec![Witness {
                    kind: "storage-closure-phase-mismatch".into(),
                    site: None,
                    symbol: None,
                    note: Some(
                        "owner and backing storage have different publication certificates".into(),
                    ),
                    extra: Extra::new(),
                }],
                recipe: None,
                diagnostics: None,
                extra: Extra::new(),
            })
        }
        _ => None,
    }
}

fn fold_localization(
    owner: Option<Localization>,
    member: Option<Localization>,
) -> Option<Localization> {
    let (Some(mut owner), Some(member)) = (owner, member) else {
        return None;
    };
    if owner.component != member.component {
        owner.verdict = LocalizationVerdict::Blocked;
        owner.blockers.push(LocalizationBlocker {
            code: "storage-closure-component-mismatch".into(),
            witness: Witness {
                kind: "storage-closure-component-mismatch".into(),
                site: None,
                symbol: None,
                note: Some(format!(
                    "owner component {} differs from backing-storage component {}",
                    owner.component, member.component
                )),
                extra: Extra::new(),
            },
            extra: Extra::new(),
        });
    } else if member.verdict == LocalizationVerdict::Blocked {
        owner.verdict = LocalizationVerdict::Blocked;
        owner.blockers.extend(member.blockers);
    }
    Some(owner)
}

#[derive(Default)]
struct RegistryAccessFacts {
    thread_visible: BTreeMap<GlobalId, Witness>,
    signal_context_access: BTreeMap<GlobalId, Witness>,
    thread_writers: BTreeMap<GlobalId, Witness>,
    /// Registration/spawn statements that act as non-routable phase-stationarity reads.
    pseudo_read_callsites: BTreeMap<GlobalId, BTreeSet<pangs_api::CallsiteId>>,
    spawn_read_callsites: BTreeMap<GlobalId, BTreeSet<pangs_api::CallsiteId>>,
    escape_read_callsites: BTreeMap<GlobalId, BTreeSet<pangs_api::CallsiteId>>,
}

fn registry_access_facts(analysis: &Analysis, module: &pangs_pir::Pir) -> RegistryAccessFacts {
    let mut result = RegistryAccessFacts::default();
    // A registry fact is existential: for each callback/global pair we only need to know
    // whether any transitive row reads it and whether any row writes it.  Keeping every row
    // here made unresolved registrations retain tens of millions of duplicate pairs.
    let mut entry_access_cache = BTreeMap::<FuncId, Vec<(GlobalId, u8)>>::new();
    let mut registry_calls = 0_u64;
    let mut registry_specs = 0_u64;
    let mut unresolved_specs = 0_u64;
    let function_ids_by_llvm_name = module
        .functions
        .iter()
        .enumerate()
        .map(|(index, function)| {
            (
                function.key.strip_prefix('@').unwrap_or(&function.key),
                FuncId(index as u32),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let address_taken_entries = analysis
        .functions()
        .iter()
        .enumerate()
        .filter(|(_, candidate)| candidate.address_taken && !candidate.external)
        .map(|(index, _)| FuncId(index as u32))
        .collect::<Vec<_>>();
    let mut callsite_index = 0_u32;
    for (caller_index, function) in module.functions.iter().enumerate() {
        let caller = FuncId(caller_index as u32);
        for stmt in &function.body {
            let (direct_callee, args, loc) = match stmt {
                pangs_pir::Stmt::CallDirect {
                    callee, args, loc, ..
                } => (Some(callee.as_str()), args, loc.as_ref()),
                pangs_pir::Stmt::CallIndirect { args, loc, .. } => (None, args, loc.as_ref()),
                _ => continue,
            };
            let callsite = pangs_api::CallsiteId(callsite_index);
            callsite_index += 1;
            let analyzed_registry = analysis.registry_entry(callsite);
            let mut specs = if let Some(entry) = analyzed_registry {
                vec![(entry.kind, 0, false)]
            } else {
                direct_callee
                    .and_then(|name| registry_spec(name, analysis.registry_apis()))
                    .into_iter()
                    .collect::<Vec<_>>()
            };
            if analyzed_registry.is_none() {
                for callee in analysis.callees(callsite) {
                    let Callee::Func(callee) = callee else {
                        continue;
                    };
                    if let Some(spec) =
                        registry_spec(&analysis.functions()[*callee].key, analysis.registry_apis())
                    {
                        if !specs.contains(&spec) {
                            specs.push(spec);
                        }
                    }
                }
            }
            for (kind, arg_index, pointee) in specs {
                registry_calls += 1;
                let operand = args.get(arg_index);
                let direct_entry = operand.and_then(|operand| {
                    let operand = operand.strip_prefix('@').unwrap_or(operand);
                    function_ids_by_llvm_name.get(operand).copied()
                });
                let solved_entry = analysis
                    .registry_entry(callsite)
                    .filter(|entry| entry.kind == kind);
                let unresolved = solved_entry
                    .map(|entry| entry.unresolved)
                    .unwrap_or(pointee || direct_entry.is_none());
                registry_specs += 1;
                unresolved_specs += u64::from(unresolved);
                let precise_entries = solved_entry
                    .map(|entry| entry.targets.clone())
                    .unwrap_or_else(|| direct_entry.into_iter().collect());
                let widened_entries = if unresolved {
                    address_taken_entries.to_vec()
                } else {
                    Vec::new()
                };
                let entries = precise_entries.into_iter().chain(widened_entries);
                let witness = registry_witness(analysis, caller, loc, kind, unresolved);
                for entry in entries {
                    let accesses = entry_access_cache.entry(entry).or_insert_with(|| {
                        let mut masks = vec![0_u8; analysis.globals().len()];
                        for (access, affected) in analysis.transitive_accesses(entry) {
                            let mask = match access {
                                pangs_pir::Access::Ref => 0b01,
                                pangs_pir::Access::Mod => 0b10,
                            };
                            match affected {
                                AffectedGlobals::Finite(globals) => {
                                    for global in globals {
                                        masks[global.0 as usize] |= mask;
                                    }
                                }
                                AffectedGlobals::ModuleWide => {
                                    for entry_mask in &mut masks {
                                        *entry_mask |= mask;
                                    }
                                }
                            }
                        }
                        masks
                            .into_iter()
                            .enumerate()
                            .filter_map(|(index, mask)| {
                                (mask != 0).then_some((GlobalId(index as u32), mask))
                            })
                            .collect()
                    });
                    for &(global, mask) in accesses.iter() {
                        match kind {
                            RegistryKind::Spawn => {
                                result
                                    .thread_visible
                                    .entry(global)
                                    .or_insert_with(|| witness.clone());
                            }
                            RegistryKind::Signal => {
                                result
                                    .signal_context_access
                                    .entry(global)
                                    .or_insert_with(|| witness.clone());
                            }
                        }
                        if mask & 0b01 != 0 {
                            result
                                .pseudo_read_callsites
                                .entry(global)
                                .or_default()
                                .insert(callsite);
                            let classified = match kind {
                                RegistryKind::Spawn => &mut result.spawn_read_callsites,
                                RegistryKind::Signal => &mut result.escape_read_callsites,
                            };
                            classified.entry(global).or_default().insert(callsite);
                        }
                        if kind == RegistryKind::Spawn && mask & 0b10 != 0 {
                            result
                                .thread_writers
                                .entry(global)
                                .or_insert_with(|| witness.clone());
                        }
                    }
                }
            }
        }
    }
    if std::env::var_os(knobs::ENV_DISPOSITION_TIMINGS).is_some() {
        eprintln!(
            "pangs disposition registry detail calls={} specs={} unresolved={} distinct-entries={} cached-accesses={}",
            registry_calls,
            registry_specs,
            unresolved_specs,
            entry_access_cache.len(),
            entry_access_cache.values().map(Vec::len).sum::<usize>(),
        );
    }
    result
}

fn registry_spec(name: &str, registries: &[RegistryApi]) -> Option<(RegistryKind, usize, bool)> {
    let name = name.strip_prefix('@').unwrap_or(name);
    let registry = registries.iter().find(|registry| registry.name == name)?;
    Some(match registry.entry {
        RegistryEntryOperand::Arg { arg } => (registry.kind, arg, false),
        RegistryEntryOperand::PointeeOfArg { pointee_of_arg } => {
            (registry.kind, pointee_of_arg, true)
        }
    })
}

fn registry_witness(
    analysis: &Analysis,
    caller: FuncId,
    loc: Option<&pangs_pir::Loc>,
    kind: RegistryKind,
    unresolved: bool,
) -> Witness {
    let caller_info = &analysis.functions()[caller];
    let symbol = caller_info
        .file
        .as_deref()
        .and_then(|file| Key::new(file, &caller_info.key).ok())
        .map(|key| key.to_string())
        .unwrap_or_else(|| caller_info.key.clone());
    Witness {
        kind: match kind {
            RegistryKind::Spawn => "spawn-reachability",
            RegistryKind::Signal => "signal-registration",
        }
        .into(),
        site: caller_info.file.as_ref().map(|file| Site {
            file: file.clone(),
            line: loc.map_or(caller_info.line.unwrap_or(0), |loc| loc.line),
            col: loc.map(|loc| loc.col),
            function: Some(symbol.clone()),
            extra: Extra::new(),
        }),
        symbol: Some(symbol),
        note: unresolved
            .then(|| "registry operand unresolved; widened to every address-taken function".into()),
        extra: Extra::new(),
    }
}

fn assemble_coupling_groups(
    analysis: &Analysis,
    globals: &mut [DispositionGlobal],
) -> Vec<CouplingGroup> {
    let keys = globals
        .iter()
        .map(|global| global.key.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let index_by_key = keys
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, key)| (key, index))
        .collect::<BTreeMap<_, _>>();
    let global_position_by_key = globals
        .iter()
        .enumerate()
        .map(|(index, global)| (global.key.clone(), index))
        .collect::<BTreeMap<_, _>>();
    let once_lock_started = Instant::now();
    let phase_by_key = globals
        .iter()
        .filter_map(|global| {
            certified_group_evidence(global).map(|evidence| (global.key.clone(), evidence))
        })
        .collect::<BTreeMap<_, _>>();
    let phase_keys = phase_by_key.keys().cloned().collect::<Vec<_>>();
    let mut once_lock_pairs = Vec::<(usize, usize, OnceLockPairEvidence)>::new();
    let mut hard_components = CouplingComponents::new(keys.len());
    for left in 0..phase_keys.len() {
        for right in left + 1..phase_keys.len() {
            let a = &phase_keys[left];
            let b = &phase_keys[right];
            let left_evidence = &phase_by_key[a];
            let right_evidence = &phase_by_key[b];
            if !once_lock_pair_compatible(left_evidence, right_evidence) {
                continue;
            }
            let a = index_by_key[a];
            let b = index_by_key[b];
            if hard_components.union(a, b) {
                let pair = once_lock_pair_evidence(left_evidence, right_evidence)
                    .expect("compatible once-lock pair must produce evidence");
                once_lock_pairs.push((a, b, pair));
            }
        }
    }
    if std::env::var_os(knobs::ENV_DISPOSITION_TIMINGS).is_some() {
        eprintln!(
            "pangs disposition timing coupling-once-lock={}ms certified-globals={} evidence-edges={}",
            once_lock_started.elapsed().as_millis(),
            phase_keys.len(),
            once_lock_pairs.len()
        );
    }

    let mut member_indexes = BTreeMap::<usize, Vec<usize>>::new();
    for index in 0..keys.len() {
        if hard_components.component_size(index) > 1 {
            member_indexes
                .entry(hard_components.find(index))
                .or_default()
                .push(index);
        }
    }
    let mut member_indexes = member_indexes.into_values().collect::<Vec<_>>();
    member_indexes.sort_by_key(|members| members[0]);
    let mut group_by_key_index = vec![None; keys.len()];
    for (group, members) in member_indexes.iter().enumerate() {
        for member in members {
            group_by_key_index[*member] = Some(group);
        }
    }
    let mut evidence_by_group = (0..member_indexes.len())
        .map(|_| Vec::new())
        .collect::<Vec<Vec<EvidenceEdge>>>();
    for (a, b, pair) in once_lock_pairs {
        let group =
            group_by_key_index[a].expect("once-lock evidence must belong to a coupling group");
        evidence_by_group[group].push(EvidenceEdge {
            kind: EvidenceKind::OncelockInterval,
            strength: EvidenceStrength::Hard,
            members: vec![keys[a].clone(), keys[b].clone()],
            sites: pair.sites,
            extra: pair.extra,
        });
    }

    let mut groups = Vec::with_capacity(member_indexes.len());
    for (group_index, indexes) in member_indexes.into_iter().enumerate() {
        let members = indexes
            .iter()
            .map(|index| keys[*index].clone())
            .collect::<Vec<_>>();
        let id = coupling_group_id(&members);
        for index in indexes {
            let key = &keys[index];
            globals[global_position_by_key[key]].facts.coupling_group = Some(id.clone());
        }
        groups.push(CouplingGroup {
            id,
            members: members.clone(),
            evidence: std::mem::take(&mut evidence_by_group[group_index]),
            strategy_support: GroupStrategySupport {
                once_lock: Some(common_once_lock_support(
                    analysis,
                    &members,
                    &phase_by_key,
                    &keys,
                )),
                mutex: None,
                extra: Extra::new(),
            },
            group_disposition: None,
            group_provenance: None,
            r#override: None,
            extra: Extra::new(),
        });
    }
    groups
}

fn assemble_atomic_eligibility(
    analysis: &Analysis,
    module: &pangs_pir::Pir,
    target: &pangs_pir::TargetInfo,
    globals: &mut [DispositionGlobal],
) -> Vec<Key> {
    let mut access_site_counts = vec![0_usize; analysis.globals().len()];
    for site in analysis.access_sites() {
        for global in site.globals() {
            access_site_counts[global.0 as usize] += 1;
        }
    }
    // Do not build the detailed access index unless at least one global has passed every coarse
    // per-global gate.
    let mut detailed_globals = vec![false; analysis.globals().len()];
    for global in globals.iter() {
        let Some(gid) = analysis.lookup_global(&global.meta.llvm_name) else {
            continue;
        };
        let width = global.facts.word_sized_scalar.size_bits;
        let signal_lock_free = !global.facts.signal_context_access.value
            || width.is_some_and(|width| target.supported_atomic_widths.contains(&width));
        detailed_globals[gid.0 as usize] = global.facts.word_sized_scalar.value
            && global.storage_members.is_empty()
            && global.facts.access_set_complete.value
            && !global.facts.violation_taint.value
            && signal_lock_free;
    }
    let mut access_by_global = vec![Vec::new(); analysis.globals().len()];
    if detailed_globals.iter().any(|&needed| needed) {
        for site in analysis.access_sites() {
            for global in site.globals() {
                if detailed_globals[global.0 as usize] {
                    access_by_global[global.0 as usize].push(site);
                }
            }
        }
    }
    let mut signal_plans = BTreeMap::<GlobalId, Result<SignalFlagPlan, Witness>>::new();
    for global in globals.iter() {
        let Some(gid) = analysis.lookup_global(&global.meta.llvm_name) else {
            continue;
        };
        if let Some(plan) = provisional_signal_flag_plan(
            analysis,
            module,
            target,
            global,
            gid,
            &access_by_global[gid.0 as usize],
        ) {
            signal_plans.insert(gid, Ok(plan));
        }
    }
    let candidate_count = signal_plans.len();
    if candidate_count != 1 {
        for (&gid, outcome) in &mut signal_plans {
            let mut witness = atomic_witness(
                "signal-flag-access-functions-not-closed",
                Some(analysis.globals()[gid].key.clone()),
                None,
                Some(format!(
                    "signal-flag-v1 requires exactly one provisional candidate; found {candidate_count}"
                )),
            );
            witness
                .extra
                .insert("candidate_count".into(), candidate_count.into());
            *outcome = Err(witness);
        }
    } else if let Some((&gid, Ok(plan))) = signal_plans.iter().next() {
        if let Err(witness) = signal_flag_function_closure(analysis, module, plan) {
            signal_plans.insert(gid, Err(witness));
        }
    }
    let mut certified_signal_flags = Vec::new();
    for global in globals {
        let Some(gid) = analysis.lookup_global(&global.meta.llvm_name) else {
            global.facts.atomic_eligibility = Some(Certificate::Failed {
                codes: vec!["global-not-in-analysis".into()],
                witnesses: vec![atomic_witness(
                    "global-not-in-analysis",
                    Some(global.key.to_string()),
                    None,
                    None,
                )],
                recipe: None,
                diagnostics: None,
                extra: Extra::new(),
            });
            continue;
        };

        let mut codes = Vec::new();
        let mut witnesses = Vec::new();
        let mut fail = |code: &str, witness: Witness| {
            codes.push(code.to_owned());
            witnesses.push(witness);
        };

        if !global.storage_members.is_empty() {
            fail(
                "nontrivial-storage-closure",
                atomic_witness(
                    "atomic-nontrivial-storage-closure",
                    Some(global.key.to_string()),
                    None,
                    Some(
                        "one atomic declaration cannot materialize compiler-generated backing storage"
                            .into(),
                    ),
                ),
            );
        }
        if !global.facts.word_sized_scalar.value {
            fail(
                "word-sized-scalar",
                atomic_witness(
                    "atomic-word-sized-scalar-failed",
                    Some(global.key.to_string()),
                    None,
                    global.meta.type_spelling.clone(),
                ),
            );
        }
        if !global.facts.access_set_complete.value {
            fail(
                "access-set-complete",
                global
                    .facts
                    .access_set_complete
                    .witness
                    .clone()
                    .unwrap_or_else(|| {
                        atomic_witness(
                            "atomic-access-set-incomplete",
                            Some(global.key.to_string()),
                            None,
                            None,
                        )
                    }),
            );
        }
        if global.facts.violation_taint.value {
            fail(
                "violation-taint",
                global
                    .facts
                    .violation_taint
                    .witness
                    .clone()
                    .unwrap_or_else(|| {
                        atomic_witness(
                            "atomic-violation-taint",
                            Some(global.key.to_string()),
                            None,
                            None,
                        )
                    }),
            );
        }
        let width = global.facts.word_sized_scalar.size_bits;
        let signal_lock_free = !global.facts.signal_context_access.value
            || width.is_some_and(|width| target.supported_atomic_widths.contains(&width));
        if !signal_lock_free {
            fail(
                "signal-atomic-not-lock-free",
                atomic_witness(
                    "signal-atomic-not-lock-free",
                    Some(global.key.to_string()),
                    None,
                    width.map(|width| format!("{width}-bit atomic is not target-guaranteed")),
                ),
            );
        }

        drop(fail);
        if !codes.is_empty() {
            global.facts.atomic_eligibility = Some(Certificate::Failed {
                codes,
                witnesses,
                recipe: None,
                diagnostics: Some(serde_json::json!({
                    "access_lowering": {
                        "status": "skipped",
                        "reason": "coarse-eligibility-failed",
                    },
                    "access_sites_observed": access_site_counts[gid.0 as usize],
                })),
                extra: Extra::new(),
            });
            continue;
        }

        let sites = &access_by_global[gid.0 as usize];
        if let Some(outcome) = signal_plans.get(&gid) {
            match outcome {
                Ok(plan) => {
                    let recipe = serde_json::json!({
                        "mode": "signal-flag-v1",
                        "declaration": atomic_declaration(analysis, global, gid),
                        "accesses": plan.accesses,
                        "cross_tu": {
                            "required": false,
                            "scope": "linked-module",
                        },
                        "ordering": "seq_cst",
                    });
                    global.facts.atomic_eligibility = Some(Certificate::Certified {
                        certificate: serde_json::json!({
                            "recipe": recipe,
                            "source_materialization": atomic_source_materialization(global),
                        }),
                        extra: Extra::new(),
                    });
                    certified_signal_flags.push(global.key.clone());
                }
                Err(witness) => {
                    global.facts.atomic_eligibility = Some(Certificate::Failed {
                        codes: vec!["signal-flag-access-functions-not-closed".into()],
                        witnesses: vec![witness.clone()],
                        recipe: None,
                        diagnostics: Some(serde_json::json!({
                            "mode": "signal-flag-v1",
                            "candidate_count": candidate_count,
                            "access_sites_observed": sites.len(),
                        })),
                        extra: Extra::new(),
                    });
                }
            }
            continue;
        }
        if let Some(evidence) = analysis.globals()[gid]
            .scalar_type_evidence
            .as_ref()
            .filter(|evidence| {
                evidence.qualifiers.is_volatile
                    && evidence
                        .typedef_chain
                        .iter()
                        .any(|name| name == "sig_atomic_t")
            })
        {
            let (code, kind, note) = if evidence.qualifiers.is_atomic {
                (
                    "source-atomic-unsupported",
                    "source-atomic-unsupported",
                    "source _Atomic ordering is not preserved by the current PIR",
                )
            } else {
                (
                    "volatile-access",
                    "atomic-volatile-access",
                    "volatile sig_atomic_t does not satisfy every signal-flag-v1 admission gate",
                )
            };
            global.facts.atomic_eligibility = Some(Certificate::Failed {
                codes: vec![code.into()],
                witnesses: vec![atomic_witness(
                    kind,
                    Some(global.key.to_string()),
                    None,
                    Some(note.into()),
                )],
                recipe: None,
                diagnostics: Some(serde_json::json!({
                    "mode": "signal-flag-v1",
                    "status": "provisional-candidate-rejected",
                    "access_sites_observed": sites.len(),
                })),
                extra: Extra::new(),
            });
            continue;
        }
        let (access_recipe, access_failures) = atomic_access_recipe(
            analysis,
            sites,
            analysis.globals()[gid].scalar_type_evidence.as_ref(),
            &global.key.to_string(),
        );
        let mut fail = |code: &str, witness: Witness| {
            codes.push(code.to_owned());
            witnesses.push(witness);
        };
        for (code, witness) in access_failures {
            fail(&code, witness);
        }
        let recipe_ready = access_recipe.is_some();
        let recipe = recipe_ready.then(|| {
            serde_json::json!({
                "mode": "ordinary",
                "declaration": atomic_declaration(analysis, global, gid),
                "accesses": access_recipe.unwrap_or_default(),
                "cross_tu": {
                    "required": global.meta.linkage == Linkage::External,
                    "scope": "linked-module",
                },
                "ordering": "relaxed",
            })
        });

        global.facts.atomic_eligibility = Some(if codes.is_empty() {
            Certificate::Certified {
                certificate: serde_json::json!({
                    "recipe": recipe.expect("a certified atomic must have a complete recipe"),
                    "source_materialization": atomic_source_materialization(global),
                }),
                extra: Extra::new(),
            }
        } else {
            Certificate::Failed {
                codes,
                witnesses,
                recipe,
                diagnostics: Some(serde_json::json!({
                    "access_sites_observed": sites.len(),
                })),
                extra: Extra::new(),
            }
        });
    }
    certified_signal_flags.sort();
    certified_signal_flags
}

fn atomic_declaration(analysis: &Analysis, global: &DispositionGlobal, gid: GlobalId) -> Value {
    serde_json::json!({
        "key": global.key,
        "llvm_name": global.meta.llvm_name,
        "file": global.meta.file,
        "line": global.meta.line,
        "type_spelling": global.meta.type_spelling,
        "size_bits": global.facts.word_sized_scalar.size_bits,
        "align_bits": global.meta.align_bits,
        "scalar_class": global.facts.word_sized_scalar.class,
        "signed": global.facts.word_sized_scalar.signed,
        "initializer_ir": analysis.globals()[gid].initializer_ir,
        "linkage": global.meta.linkage,
    })
}

#[derive(Clone)]
struct SignalFlagPlan {
    accesses: Vec<Value>,
    access_functions: BTreeSet<FuncId>,
    operation_statements: BTreeSet<(FuncId, u32)>,
}

fn provisional_signal_flag_plan(
    analysis: &Analysis,
    module: &pangs_pir::Pir,
    target: &pangs_pir::TargetInfo,
    global: &DispositionGlobal,
    gid: GlobalId,
    sites: &[&pangs_api::AccessSite],
) -> Option<SignalFlagPlan> {
    let info = &analysis.globals()[gid];
    let evidence = info.scalar_type_evidence.as_ref()?;
    let qualifiers = &evidence.qualifiers;
    let target_arch = target.triple.split('-').next();
    if !info.is_definition
        || !info.mutable
        || info.initializer_ir.is_none()
        || info.linkage != pangs_pir::SymbolLinkage::Internal
        || info.section.is_some()
        || info.thread_local
        || !evidence
            .typedef_chain
            .iter()
            .any(|name| name == "sig_atomic_t")
        || !qualifiers.is_volatile
        || qualifiers.is_const
        || qualifiers.is_atomic
        || evidence.class != Some(pangs_pir::ScalarTypeClass::Integer)
        || evidence.signed != Some(true)
        || target_arch != Some("x86_64")
        || info.size_bits != Some(32)
        || info.align_bits != Some(32)
        || !global.facts.access_set_complete.value
        || !global.facts.word_sized_scalar.value
        || global.facts.violation_taint.value
        || !global.storage_members.is_empty()
        || info.address_escaped
        || module.globals.iter().any(|candidate| {
            candidate
                .init_refs
                .iter()
                .any(|referenced| same_llvm_global(referenced, &info.key))
        })
        || sites.is_empty()
    {
        return None;
    }

    let mut ordered = sites.to_vec();
    ordered.sort_by_key(|site| (site.func, site.statement_index, site.access, site.via));
    let mut accesses = Vec::with_capacity(ordered.len());
    let mut access_functions = BTreeSet::new();
    let mut operation_statements = BTreeSet::new();
    for site in ordered {
        if site.via != pangs_api::Via::Direct
            || !site.volatile
            || site.atomic_rmw.is_some()
            || site.loc.is_none()
            || site.globals().ne(std::iter::once(gid))
        {
            return None;
        }
        let reference_index = site.statement_index? as usize;
        let function_key = &analysis.functions()[site.func].key;
        let function = module
            .functions
            .iter()
            .find(|function| &function.key == function_key)?;
        let operation_index = reference_index.checked_sub(1)?;
        let global_ref_matches = matches!(
            function.body.get(reference_index),
            Some(pangs_pir::Stmt::GlobalRef { global: referenced, access, volatile: true, .. })
                if same_llvm_global(referenced, &info.key) && *access == site.access
        );
        if !global_ref_matches {
            return None;
        }
        let operation_matches = match (site.access, function.body.get(operation_index)) {
            (
                pangs_pir::Access::Ref,
                Some(pangs_pir::Stmt::Load {
                    address,
                    volatile: true,
                    access_bytes: Some(4),
                    ..
                }),
            ) => same_llvm_global(address, &info.key),
            (
                pangs_pir::Access::Mod,
                Some(pangs_pir::Stmt::Store {
                    address,
                    volatile: true,
                    access_bytes: Some(4),
                    ..
                }),
            ) => same_llvm_global(address, &info.key),
            _ => false,
        };
        if !operation_matches {
            return None;
        }
        access_functions.insert(site.func);
        operation_statements.insert((site.func, operation_index as u32));
        accesses.push(serde_json::json!({
            "operation": if site.access == pangs_pir::Access::Ref { "load" } else { "store" },
            "function": function_key,
            "site": atomic_access_site(analysis, site),
            "statement_index": site.statement_index,
        }));
    }
    Some(SignalFlagPlan {
        accesses,
        access_functions,
        operation_statements,
    })
}

fn signal_flag_function_closure(
    analysis: &Analysis,
    module: &pangs_pir::Pir,
    plan: &SignalFlagPlan,
) -> Result<(), Witness> {
    for &func_id in &plan.access_functions {
        let function_key = &analysis.functions()[func_id].key;
        let Some(function) = module
            .functions
            .iter()
            .find(|function| &function.key == function_key)
        else {
            let mut witness = atomic_witness(
                "signal-flag-access-functions-not-closed",
                Some(function_key.clone()),
                None,
                Some("candidate access function is absent from PIR".into()),
            );
            witness
                .extra
                .insert("function".into(), function_key.clone().into());
            return Err(witness);
        };
        for (statement_index, statement) in function.body.iter().enumerate() {
            let (operation, address, loc) = match statement {
                pangs_pir::Stmt::Load {
                    address,
                    volatile: true,
                    loc,
                    ..
                } => ("load", address, loc),
                pangs_pir::Stmt::Store {
                    address,
                    volatile: true,
                    loc,
                    ..
                } => ("store", address, loc),
                _ => continue,
            };
            if plan
                .operation_statements
                .contains(&(func_id, statement_index as u32))
            {
                continue;
            }
            let site = loc.as_ref().map(|loc| Site {
                file: loc.file.clone(),
                line: loc.line,
                col: Some(loc.col),
                function: Some(function_key.clone()),
                extra: Extra::new(),
            });
            let mut witness = atomic_witness(
                "signal-flag-access-functions-not-closed",
                Some(function_key.clone()),
                site,
                Some(format!(
                    "unrelated volatile {operation} at statement {statement_index} through {address}"
                )),
            );
            witness
                .extra
                .insert("function".into(), function_key.clone().into());
            witness
                .extra
                .insert("statement_index".into(), statement_index.into());
            witness.extra.insert("operation".into(), operation.into());
            witness
                .extra
                .insert("address_operand".into(), address.clone().into());
            if let Some(global) = address.strip_prefix('@') {
                witness
                    .extra
                    .insert("attributable_global".into(), global.into());
            }
            return Err(witness);
        }
    }
    Ok(())
}

fn same_llvm_global(operand: &str, global: &str) -> bool {
    operand.strip_prefix('@').unwrap_or(operand) == global.strip_prefix('@').unwrap_or(global)
}

fn atomic_source_materialization(global: &DispositionGlobal) -> serde_json::Value {
    if global.meta.file.is_some() && global.meta.line.is_some() {
        serde_json::json!({
            "status": "source-mapped",
        })
    } else {
        serde_json::json!({
            "status": "blocked",
            "code": "declaration-source-unmapped",
            "detail": "static eligibility is certified, but the C declaration requires symbol-based source recovery",
        })
    }
}

#[derive(Clone, Copy)]
struct MutexCallStep {
    callee: FuncId,
    callsite: Option<pangs_api::CallsiteId>,
}

#[derive(Clone, PartialEq, Eq)]
struct MutexUnknownStep {
    reason: String,
    callsite: Option<pangs_api::CallsiteId>,
}

struct MutexReachability {
    outgoing: Vec<Vec<MutexCallStep>>,
    unknown_outgoing: Vec<Vec<MutexUnknownStep>>,
}

impl MutexReachability {
    fn new(analysis: &Analysis) -> Self {
        let mut outgoing = vec![Vec::new(); analysis.functions().len()];
        let mut unknown_outgoing = vec![Vec::new(); analysis.functions().len()];
        for edge in analysis.call_edges() {
            let Caller::Func(caller) = &edge.caller else {
                continue;
            };
            match &edge.callee {
                Callee::Func(callee) => outgoing[caller.0 as usize].push(MutexCallStep {
                    callee: *callee,
                    callsite: edge.callsite,
                }),
                Callee::Unknown(reason) => {
                    unknown_outgoing[caller.0 as usize].push(MutexUnknownStep {
                        reason: reason.clone(),
                        callsite: edge.callsite,
                    });
                }
            }
        }
        for edges in &mut outgoing {
            edges.sort_by_key(|edge| (edge.callee, edge.callsite));
            edges.dedup_by_key(|edge| (edge.callee, edge.callsite));
        }
        for edges in &mut unknown_outgoing {
            edges.sort_by(|left, right| {
                (&left.reason, left.callsite).cmp(&(&right.reason, right.callsite))
            });
            edges.dedup_by(|left, right| {
                left.reason == right.reason && left.callsite == right.callsite
            });
        }
        Self {
            outgoing,
            unknown_outgoing,
        }
    }

    /// Find a non-empty final-call-graph path from an accessor to an accessor. A direct or
    /// indirect recursive edge therefore fails, while the zero-length identity path does not.
    fn accessor_path(&self, accessors: &BTreeSet<FuncId>) -> Option<Vec<(FuncId, MutexCallStep)>> {
        for &source in accessors {
            let mut seen = vec![false; self.outgoing.len()];
            let mut parent = vec![None::<(FuncId, MutexCallStep)>; self.outgoing.len()];
            let mut queue = VecDeque::new();
            seen[source.0 as usize] = true;
            queue.push_back(source);
            while let Some(caller) = queue.pop_front() {
                for &step in &self.outgoing[caller.0 as usize] {
                    if accessors.contains(&step.callee) {
                        let mut path = vec![(caller, step)];
                        let mut cursor = caller;
                        while cursor != source {
                            let (previous, previous_step) = parent[cursor.0 as usize]
                                .expect("BFS-discovered function must have a parent");
                            path.push((previous, previous_step));
                            cursor = previous;
                        }
                        path.reverse();
                        return Some(path);
                    }
                    if !seen[step.callee.0 as usize] {
                        seen[step.callee.0 as usize] = true;
                        parent[step.callee.0 as usize] = Some((caller, step));
                        queue.push_back(step.callee);
                    }
                }
            }
        }
        None
    }

    /// Find a known path from an accessor to a call with an unresolved target. Under the v1
    /// whole-function lock scope, the unknown target may call back into any accessor.
    fn unknown_callee_path(
        &self,
        accessors: &BTreeSet<FuncId>,
    ) -> Option<(Vec<(FuncId, MutexCallStep)>, FuncId, MutexUnknownStep)> {
        for &source in accessors {
            let mut seen = vec![false; self.outgoing.len()];
            let mut parent = vec![None::<(FuncId, MutexCallStep)>; self.outgoing.len()];
            let mut queue = VecDeque::new();
            seen[source.0 as usize] = true;
            queue.push_back(source);
            while let Some(caller) = queue.pop_front() {
                if let Some(unknown) = self.unknown_outgoing[caller.0 as usize].first() {
                    let mut path = Vec::new();
                    let mut cursor = caller;
                    while cursor != source {
                        let (previous, previous_step) = parent[cursor.0 as usize]
                            .expect("BFS-discovered function must have a parent");
                        path.push((previous, previous_step));
                        cursor = previous;
                    }
                    path.reverse();
                    return Some((path, caller, unknown.clone()));
                }
                for &step in &self.outgoing[caller.0 as usize] {
                    if !seen[step.callee.0 as usize] {
                        seen[step.callee.0 as usize] = true;
                        parent[step.callee.0 as usize] = Some((caller, step));
                        queue.push_back(step.callee);
                    }
                }
            }
        }
        None
    }

    fn reachable_unknown_callees(
        &self,
        accessors: &BTreeSet<FuncId>,
    ) -> Vec<(FuncId, MutexUnknownStep)> {
        let mut seen = vec![false; self.outgoing.len()];
        let mut queue = VecDeque::new();
        for &accessor in accessors {
            if !seen[accessor.0 as usize] {
                seen[accessor.0 as usize] = true;
                queue.push_back(accessor);
            }
        }
        let mut unknown = Vec::new();
        while let Some(caller) = queue.pop_front() {
            unknown.extend(
                self.unknown_outgoing[caller.0 as usize]
                    .iter()
                    .cloned()
                    .map(|step| (caller, step)),
            );
            for step in &self.outgoing[caller.0 as usize] {
                if !seen[step.callee.0 as usize] {
                    seen[step.callee.0 as usize] = true;
                    queue.push_back(step.callee);
                }
            }
        }
        unknown.sort_by(|left, right| {
            (left.0, &left.1.reason, left.1.callsite).cmp(&(
                right.0,
                &right.1.reason,
                right.1.callsite,
            ))
        });
        unknown.dedup_by(|left, right| left == right);
        unknown
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ExternalPolicyD4Census {
    pub globals: Vec<ExternalPolicyD4GlobalRow>,
    pub module_wide_leave_one_out: Vec<ModuleWideLeaveOneOutRow>,
    pub forged_pointer_group_counterfactuals: Vec<ForgedPointerGroupCounterfactual>,
    pub module_wide_remove_all_counterfactual: ModuleWideSetCounterfactual,
    pub feasible_forged_groups_counterfactual: ModuleWideSetCounterfactual,
    pub bounded_constant_groups_counterfactual: ModuleWideSetCounterfactual,
    pub summary: ExternalPolicyD4Summary,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ExternalPolicyD4Summary {
    pub globals_evaluated: usize,
    pub strict_mutex_eligible: usize,
    pub strict_unknown_callee_reentrancy_failures: usize,
    pub accessor_reachable_unknown_pairs: usize,
    pub complete_accessor_disjoint_pairs: usize,
    pub accessor_reaching_pairs: usize,
    pub incomplete_control_pairs: usize,
    pub ideal_newly_mutex_eligible: usize,
    pub module_wide_leave_one_out_newly_access_complete: usize,
    pub module_wide_leave_one_out_newly_mutex_eligible_under_strict_reentry: usize,
    pub forged_pointer_group_newly_access_complete: usize,
    pub forged_pointer_group_newly_mutex_eligible_under_strict_reentry: usize,
    pub module_wide_remove_all_newly_access_complete: usize,
    pub module_wide_remove_all_newly_mutex_eligible_under_strict_reentry: usize,
    pub feasible_forged_groups_newly_access_complete: usize,
    pub feasible_forged_groups_newly_mutex_eligible_under_strict_reentry: usize,
    pub bounded_constant_groups_newly_access_complete: usize,
    pub bounded_constant_groups_newly_mutex_eligible_under_strict_reentry: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExternalPolicyD4GlobalRow {
    pub global: String,
    pub accessor_functions: Vec<String>,
    pub strict_mutex_codes: Vec<String>,
    pub coarse_preconditions_complete: bool,
    pub known_accessor_reentry: bool,
    pub unknown_calls: Vec<ExternalPolicyD4UnknownCall>,
    pub all_unknown_calls_certifiable_and_disjoint: bool,
    pub ideal_conventional_mutex_eligible: bool,
    pub ideal_newly_mutex_eligible: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExternalPolicyD4UnknownCall {
    pub callsite: Option<u32>,
    pub caller: String,
    pub reason: String,
    pub principal: Option<String>,
    pub control_closure_complete: bool,
    pub reaches_accessor: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleWideLeaveOneOutRow {
    pub modref_row_index: usize,
    pub seed_kinds: Vec<String>,
    pub poisoned_globals: usize,
    pub newly_access_complete_globals: Vec<String>,
    pub newly_mutex_eligible_under_strict_reentry: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ForgedPointerGroupCounterfactual {
    pub group: String,
    pub feasibly_certifiable: bool,
    pub removed_modref_rows: usize,
    pub remaining_module_wide_rows: usize,
    pub finite_candidate_globals: Vec<String>,
    pub newly_access_complete_globals: Vec<String>,
    pub newly_mutex_eligible_under_strict_reentry: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ModuleWideSetCounterfactual {
    pub removed_groups: usize,
    pub removed_modref_rows: usize,
    pub remaining_module_wide_rows: usize,
    pub newly_access_complete_globals: Vec<String>,
    pub newly_mutex_eligible_under_strict_reentry: Vec<String>,
}

/// Counterfactual D4 census for the proposed conventional external-code policy.
///
/// This consumes diagnostic control closures but never feeds a result back into disposition.
pub fn external_policy_d4_census(
    analysis: &Analysis,
    manifest: &DispositionManifest,
) -> ExternalPolicyD4Census {
    let reachability = MutexReachability::new(analysis);
    let control = analysis
        .external_policy_census()
        .map(|census| {
            census
                .opaque_callsites
                .iter()
                .map(|row| (row.callsite, row))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let principals = analysis
        .external_policy_census()
        .map(|census| {
            census
                .principals
                .iter()
                .map(|row| (row.principal.as_str(), row))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let mut accessors_by_global = vec![BTreeSet::new(); analysis.globals().len()];
    for site in analysis.access_sites() {
        for global in site.globals() {
            accessors_by_global[global.0 as usize].insert(site.func);
        }
    }

    let mut rows = Vec::new();
    for global in &manifest.globals {
        let accessors = storage_closure_gids(analysis, global)
            .iter()
            .flat_map(|gid| &accessors_by_global[gid.0 as usize])
            .copied()
            .collect::<BTreeSet<_>>();
        let known_accessor_reentry = reachability.accessor_path(&accessors).is_some();
        let strict_mutex_codes = match global.facts.mutex_eligibility.as_ref() {
            Some(Certificate::Failed { codes, .. }) => codes.clone(),
            _ => Vec::new(),
        };
        let strict_mutex_eligible = global
            .facts
            .mutex_eligibility
            .as_ref()
            .is_some_and(Certificate::is_certified);
        let coarse_preconditions_complete = global.facts.access_set_complete.value
            && !global.facts.signal_context_access.value
            && !global.facts.violation_taint.value;
        let unknown_calls = reachability
            .reachable_unknown_callees(&accessors)
            .into_iter()
            .map(|(caller, unknown)| {
                let control_row = unknown
                    .callsite
                    .and_then(|callsite| control.get(&callsite.0));
                let principal_row = control_row
                    .and_then(|row| principals.get(row.principal.as_str()))
                    .copied();
                let reaches_accessor = principal_row
                    .into_iter()
                    .flat_map(|row| &row.reachable_internal_functions)
                    .any(|name| {
                        analysis
                            .lookup_func(name)
                            .is_some_and(|function| accessors.contains(&function))
                    });
                ExternalPolicyD4UnknownCall {
                    callsite: unknown.callsite.map(|callsite| callsite.0),
                    caller: analysis.functions()[caller].key.clone(),
                    reason: unknown.reason,
                    principal: control_row.map(|row| row.principal.clone()),
                    control_closure_complete: principal_row
                        .is_some_and(|row| row.control_closure_complete),
                    reaches_accessor,
                }
            })
            .collect::<Vec<_>>();
        let all_unknown_calls_certifiable_and_disjoint = unknown_calls
            .iter()
            .all(|call| call.control_closure_complete && !call.reaches_accessor);
        let ideal_conventional_mutex_eligible = coarse_preconditions_complete
            && !known_accessor_reentry
            && all_unknown_calls_certifiable_and_disjoint;
        rows.push(ExternalPolicyD4GlobalRow {
            global: global.meta.llvm_name.clone(),
            accessor_functions: accessors
                .iter()
                .map(|function| analysis.functions()[*function].key.clone())
                .collect(),
            strict_mutex_codes,
            coarse_preconditions_complete,
            known_accessor_reentry,
            unknown_calls,
            all_unknown_calls_certifiable_and_disjoint,
            ideal_conventional_mutex_eligible,
            ideal_newly_mutex_eligible: !strict_mutex_eligible && ideal_conventional_mutex_eligible,
        });
    }

    let row_by_global = rows
        .iter()
        .map(|row| (row.global.as_str(), row))
        .collect::<BTreeMap<_, _>>();
    let module_wide_leave_one_out = analysis
        .external_policy_census()
        .into_iter()
        .flat_map(|census| &census.module_wide_rows)
        .map(|row| {
            let newly_access_complete_globals = row.exclusively_poisoned_globals.clone();
            let newly_mutex_eligible_under_strict_reentry = newly_access_complete_globals
                .iter()
                .filter(|global| {
                    let Some(record) = manifest
                        .globals
                        .iter()
                        .find(|record| record.meta.llvm_name.as_str() == global.as_str())
                    else {
                        return false;
                    };
                    let Some(d4) = row_by_global.get(global.as_str()) else {
                        return false;
                    };
                    !record.facts.signal_context_access.value
                        && !record.facts.violation_taint.value
                        && !d4.known_accessor_reentry
                        && d4.unknown_calls.is_empty()
                })
                .cloned()
                .collect();
            ModuleWideLeaveOneOutRow {
                modref_row_index: row.row_index,
                seed_kinds: row.seed_kinds.clone(),
                poisoned_globals: row.poisoned_globals,
                newly_access_complete_globals,
                newly_mutex_eligible_under_strict_reentry,
            }
        })
        .collect::<Vec<_>>();

    let core_census = analysis.external_policy_census();
    let module_wide_row_count = core_census
        .map(|census| census.module_wide_rows.len())
        .unwrap_or(0);
    let counterfactual_for_remaining = |remaining_module_wide_rows: usize| {
        let newly_access_complete_globals = if remaining_module_wide_rows == 0 {
            analysis
                .globals()
                .iter()
                .filter(|info| {
                    let currently_incomplete = manifest.globals.iter().any(|global| {
                        global.meta.llvm_name == info.key && !global.facts.access_set_complete.value
                    });
                    currently_incomplete
                        && !info.address_escaped
                        && !(core_census
                            .is_some_and(|census| census.build_mode == BuildMode::Library)
                            && info.exported)
                })
                .map(|info| info.key.clone())
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let newly_mutex_eligible_under_strict_reentry = newly_access_complete_globals
            .iter()
            .filter(|global| {
                let Some(record) = manifest
                    .globals
                    .iter()
                    .find(|record| record.meta.llvm_name.as_str() == global.as_str())
                else {
                    return false;
                };
                let Some(d4) = row_by_global.get(global.as_str()) else {
                    return false;
                };
                !record.facts.signal_context_access.value
                    && !record.facts.violation_taint.value
                    && !d4.known_accessor_reentry
                    && d4.unknown_calls.is_empty()
            })
            .cloned()
            .collect::<Vec<_>>();
        (
            newly_access_complete_globals,
            newly_mutex_eligible_under_strict_reentry,
        )
    };
    let forged_pointer_group_counterfactuals = core_census
        .into_iter()
        .flat_map(|census| &census.forged_pointer_groups)
        .map(|group| {
            let removed = group.modref_row_indices.len();
            let remaining = module_wide_row_count.saturating_sub(removed);
            let (newly_access_complete_globals, newly_mutex_eligible_under_strict_reentry) =
                counterfactual_for_remaining(remaining);
            ForgedPointerGroupCounterfactual {
                group: group.group.clone(),
                feasibly_certifiable: group.feasibly_certifiable,
                removed_modref_rows: removed,
                remaining_module_wide_rows: remaining,
                finite_candidate_globals: group.finite_candidate_globals.clone(),
                newly_access_complete_globals,
                newly_mutex_eligible_under_strict_reentry,
            }
        })
        .collect::<Vec<_>>();
    let group_count = forged_pointer_group_counterfactuals.len();
    let feasible_groups = core_census
        .into_iter()
        .flat_map(|census| &census.forged_pointer_groups)
        .filter(|group| group.feasibly_certifiable)
        .collect::<Vec<_>>();
    let feasible_removed_rows = feasible_groups
        .iter()
        .map(|group| group.modref_row_indices.len())
        .sum::<usize>();
    let feasible_remaining_rows = module_wide_row_count.saturating_sub(feasible_removed_rows);
    let (feasible_new_access, feasible_new_mutex) =
        counterfactual_for_remaining(feasible_remaining_rows);
    let feasible_forged_groups_counterfactual = ModuleWideSetCounterfactual {
        removed_groups: feasible_groups.len(),
        removed_modref_rows: feasible_removed_rows,
        remaining_module_wide_rows: feasible_remaining_rows,
        newly_access_complete_globals: feasible_new_access,
        newly_mutex_eligible_under_strict_reentry: feasible_new_mutex,
    };
    let bounded_constant_groups = core_census
        .into_iter()
        .flat_map(|census| &census.forged_pointer_groups)
        .filter(|group| group.feasibly_certifiable || group.bounded_constant_candidate)
        .collect::<Vec<_>>();
    let bounded_constant_removed_rows = bounded_constant_groups
        .iter()
        .map(|group| group.modref_row_indices.len())
        .sum::<usize>();
    let bounded_constant_remaining_rows =
        module_wide_row_count.saturating_sub(bounded_constant_removed_rows);
    let (bounded_constant_new_access, bounded_constant_new_mutex) =
        counterfactual_for_remaining(bounded_constant_remaining_rows);
    let bounded_constant_groups_counterfactual = ModuleWideSetCounterfactual {
        removed_groups: bounded_constant_groups.len(),
        removed_modref_rows: bounded_constant_removed_rows,
        remaining_module_wide_rows: bounded_constant_remaining_rows,
        newly_access_complete_globals: bounded_constant_new_access,
        newly_mutex_eligible_under_strict_reentry: bounded_constant_new_mutex,
    };
    let (all_new_access, all_new_mutex) = counterfactual_for_remaining(0);
    let module_wide_remove_all_counterfactual = ModuleWideSetCounterfactual {
        removed_groups: group_count,
        removed_modref_rows: module_wide_row_count,
        remaining_module_wide_rows: 0,
        newly_access_complete_globals: all_new_access,
        newly_mutex_eligible_under_strict_reentry: all_new_mutex,
    };

    let summary = ExternalPolicyD4Summary {
        globals_evaluated: rows.len(),
        strict_mutex_eligible: rows
            .iter()
            .filter(|row| row.strict_mutex_codes.is_empty())
            .count(),
        strict_unknown_callee_reentrancy_failures: rows
            .iter()
            .filter(|row| {
                row.strict_mutex_codes
                    .iter()
                    .any(|code| code == "unknown-callee-reentrancy")
            })
            .count(),
        accessor_reachable_unknown_pairs: rows.iter().map(|row| row.unknown_calls.len()).sum(),
        complete_accessor_disjoint_pairs: rows
            .iter()
            .flat_map(|row| &row.unknown_calls)
            .filter(|call| call.control_closure_complete && !call.reaches_accessor)
            .count(),
        accessor_reaching_pairs: rows
            .iter()
            .flat_map(|row| &row.unknown_calls)
            .filter(|call| call.reaches_accessor)
            .count(),
        incomplete_control_pairs: rows
            .iter()
            .flat_map(|row| &row.unknown_calls)
            .filter(|call| !call.control_closure_complete)
            .count(),
        ideal_newly_mutex_eligible: rows
            .iter()
            .filter(|row| row.ideal_newly_mutex_eligible)
            .count(),
        module_wide_leave_one_out_newly_access_complete: module_wide_leave_one_out
            .iter()
            .map(|row| row.newly_access_complete_globals.len())
            .sum(),
        module_wide_leave_one_out_newly_mutex_eligible_under_strict_reentry:
            module_wide_leave_one_out
                .iter()
                .map(|row| row.newly_mutex_eligible_under_strict_reentry.len())
                .sum(),
        forged_pointer_group_newly_access_complete: forged_pointer_group_counterfactuals
            .iter()
            .map(|row| row.newly_access_complete_globals.len())
            .sum(),
        forged_pointer_group_newly_mutex_eligible_under_strict_reentry:
            forged_pointer_group_counterfactuals
                .iter()
                .map(|row| row.newly_mutex_eligible_under_strict_reentry.len())
                .sum(),
        module_wide_remove_all_newly_access_complete: module_wide_remove_all_counterfactual
            .newly_access_complete_globals
            .len(),
        module_wide_remove_all_newly_mutex_eligible_under_strict_reentry:
            module_wide_remove_all_counterfactual
                .newly_mutex_eligible_under_strict_reentry
                .len(),
        feasible_forged_groups_newly_access_complete: feasible_forged_groups_counterfactual
            .newly_access_complete_globals
            .len(),
        feasible_forged_groups_newly_mutex_eligible_under_strict_reentry:
            feasible_forged_groups_counterfactual
                .newly_mutex_eligible_under_strict_reentry
                .len(),
        bounded_constant_groups_newly_access_complete: bounded_constant_groups_counterfactual
            .newly_access_complete_globals
            .len(),
        bounded_constant_groups_newly_mutex_eligible_under_strict_reentry:
            bounded_constant_groups_counterfactual
                .newly_mutex_eligible_under_strict_reentry
                .len(),
    };
    ExternalPolicyD4Census {
        globals: rows,
        module_wide_leave_one_out,
        forged_pointer_group_counterfactuals,
        module_wide_remove_all_counterfactual,
        feasible_forged_groups_counterfactual,
        bounded_constant_groups_counterfactual,
        summary,
    }
}

fn assemble_mutex_eligibility(
    analysis: &Analysis,
    reachability: &MutexReachability,
    globals: &mut [DispositionGlobal],
) {
    let mut accessors_by_global = vec![BTreeSet::new(); analysis.globals().len()];
    let mut access_site_counts = vec![0_usize; analysis.globals().len()];
    for site in analysis.access_sites() {
        for global in site.globals() {
            accessors_by_global[global.0 as usize].insert(site.func);
            access_site_counts[global.0 as usize] += 1;
        }
    }

    for global in globals {
        let Some(gid) = analysis.lookup_global(&global.meta.llvm_name) else {
            global.facts.mutex_eligibility = Some(Certificate::Failed {
                codes: vec!["global-not-in-analysis".into()],
                witnesses: vec![mutex_witness(
                    "mutex-global-not-in-analysis",
                    Some(global.key.to_string()),
                    None,
                    None,
                )],
                recipe: None,
                diagnostics: None,
                extra: Extra::new(),
            });
            continue;
        };

        let mut codes = Vec::new();
        let mut witnesses = Vec::new();
        if !global.facts.access_set_complete.value {
            codes.push("access-set-complete".into());
            witnesses.push(
                global
                    .facts
                    .access_set_complete
                    .witness
                    .clone()
                    .unwrap_or_else(|| {
                        mutex_witness(
                            "mutex-access-set-incomplete",
                            Some(global.key.to_string()),
                            None,
                            None,
                        )
                    }),
            );
        }
        if global.facts.signal_context_access.value {
            codes.push("signal-context-access".into());
            witnesses.push(
                global
                    .facts
                    .signal_context_access
                    .witness
                    .clone()
                    .unwrap_or_else(|| {
                        mutex_witness(
                            "mutex-signal-context-access",
                            Some(global.key.to_string()),
                            None,
                            None,
                        )
                    }),
            );
        }
        if global.facts.violation_taint.value {
            codes.push("violation-taint".into());
            witnesses.push(
                global
                    .facts
                    .violation_taint
                    .witness
                    .clone()
                    .unwrap_or_else(|| {
                        mutex_witness(
                            "mutex-violation-taint",
                            Some(global.key.to_string()),
                            None,
                            None,
                        )
                    }),
            );
        }

        let closure_gids = storage_closure_gids(analysis, global);
        let accessors = closure_gids
            .iter()
            .flat_map(|gid| &accessors_by_global[gid.0 as usize])
            .copied()
            .collect::<BTreeSet<_>>();
        let access_site_count = closure_gids
            .iter()
            .map(|gid| access_site_counts[gid.0 as usize])
            .sum::<usize>();
        if codes.is_empty() {
            if let Some(path) = reachability.accessor_path(&accessors) {
                codes.push("reentrant-access-path".into());
                witnesses.push(mutex_path_witness(analysis, &global.key.to_string(), &path));
            }
            if let Some((path, caller, unknown)) = reachability.unknown_callee_path(&accessors) {
                codes.push("unknown-callee-reentrancy".into());
                witnesses.push(mutex_unknown_callee_witness(
                    analysis,
                    &global.key.to_string(),
                    &path,
                    caller,
                    &unknown,
                ));
            }
        }

        let accessor_functions = accessors
            .iter()
            .map(|func| analysis.functions()[*func].key.clone())
            .collect::<Vec<_>>();
        global.facts.mutex_eligibility = Some(if codes.is_empty() {
            Certificate::Certified {
                certificate: serde_json::json!({
                    "accessor_functions": accessor_functions,
                    "declaration": mutex_declaration(analysis, global, gid),
                    "reentrancy": {
                        "model": "final-call-graph-v1",
                        "status": "no-accessor-reachable-from-accessor",
                    },
                    "lock_recipe": {
                        "granularity": "per-global",
                        "scope": "whole-accessor-function-v1",
                        "dynamic_audit": "lock-cycle-detection-required",
                    },
                    "source_materialization": mutex_source_materialization(
                        global,
                        accessors.len(),
                    ),
                }),
                extra: Extra::new(),
            }
        } else {
            Certificate::Failed {
                codes,
                witnesses,
                recipe: None,
                diagnostics: Some(serde_json::json!({
                    "access_sites_observed": access_site_count,
                    "accessor_functions": accessor_functions,
                    "reentrancy_check": if global.facts.access_set_complete.value
                        && !global.facts.signal_context_access.value
                        && !global.facts.violation_taint.value
                    { "performed" } else { "skipped-coarse-eligibility-failed" },
                })),
                extra: Extra::new(),
            }
        });
    }
}

fn mutex_declaration(
    analysis: &Analysis,
    global: &DispositionGlobal,
    gid: GlobalId,
) -> serde_json::Value {
    serde_json::json!({
        "key": global.key,
        "llvm_name": global.meta.llvm_name,
        "file": global.meta.file,
        "line": global.meta.line,
        "type_spelling": global.meta.type_spelling,
        "size_bits": global.meta.size_bits,
        "align_bits": global.meta.align_bits,
        "initializer_ir": analysis.globals()[gid].initializer_ir,
        "linkage": global.meta.linkage,
        "storage_members": global.storage_members,
    })
}

fn storage_closure_gids(analysis: &Analysis, global: &DispositionGlobal) -> Vec<GlobalId> {
    std::iter::once(global.meta.llvm_name.as_str())
        .chain(
            global
                .storage_members
                .iter()
                .map(|member| member.llvm_name.as_str()),
        )
        .filter_map(|name| analysis.lookup_global(name))
        .collect()
}

fn mutex_source_materialization(
    global: &DispositionGlobal,
    accessor_count: usize,
) -> serde_json::Value {
    if global.meta.file.is_none() || global.meta.line.is_none() {
        serde_json::json!({
            "status": "blocked",
            "code": "declaration-source-unmapped",
            "detail": "static eligibility is certified, but the C declaration requires symbol-based source recovery",
        })
    } else if accessor_count == 0 {
        serde_json::json!({
            "status": "blocked",
            "code": "no-runtime-accessor-sites",
            "detail": "static eligibility is certified, but the whole-accessor-function lock recipe has no runtime insertion site",
        })
    } else {
        serde_json::json!({
            "status": "source-mapped",
        })
    }
}

fn assemble_group_mutex_support(
    analysis: &Analysis,
    reachability: &MutexReachability,
    globals: &[DispositionGlobal],
    groups: &mut [CouplingGroup],
) {
    let global_by_key = globals
        .iter()
        .map(|global| (global.key.clone(), global))
        .collect::<BTreeMap<_, _>>();
    let mut accessors_by_global = vec![BTreeSet::new(); analysis.globals().len()];
    for site in analysis.access_sites() {
        for global in site.globals() {
            accessors_by_global[global.0 as usize].insert(site.func);
        }
    }

    for group in groups {
        let mut accessors = BTreeSet::new();
        let mut member_failures = Vec::new();
        for member in &group.members {
            let Some(global) = global_by_key.get(member) else {
                member_failures.push(mutex_witness(
                    "mutex-group-member-missing",
                    Some(member.to_string()),
                    None,
                    Some(group.id.clone()),
                ));
                continue;
            };
            if !global
                .facts
                .mutex_eligibility
                .as_ref()
                .is_some_and(Certificate::is_certified)
            {
                member_failures.push(mutex_witness(
                    "mutex-group-member-ineligible",
                    Some(member.to_string()),
                    None,
                    Some(group.id.clone()),
                ));
            }
            for gid in storage_closure_gids(analysis, global) {
                accessors.extend(&accessors_by_global[gid.0 as usize]);
            }
        }

        if !member_failures.is_empty() {
            group.strategy_support.mutex = Some(Certificate::Failed {
                codes: vec!["group-member-ineligible".into()],
                witnesses: member_failures,
                recipe: None,
                diagnostics: Some(serde_json::json!({
                    "lock_granularity": "shared-group",
                    "group": group.id,
                    "members": group.members,
                    "reentrancy_check": "skipped-member-eligibility-failed",
                })),
                extra: Extra::new(),
            });
            continue;
        }

        group.strategy_support.mutex = Some(match reachability.accessor_path(&accessors) {
            Some(path) => Certificate::Failed {
                codes: vec!["group-reentrant-access-path".into()],
                witnesses: vec![mutex_path_witness(analysis, &group.id, &path)],
                recipe: None,
                diagnostics: Some(serde_json::json!({
                    "lock_granularity": "shared-group",
                    "group": group.id,
                    "members": group.members,
                    "accessor_functions": accessors.iter().map(|func| analysis.functions()[*func].key.clone()).collect::<Vec<_>>(),
                })),
                extra: Extra::new(),
            },
            None => Certificate::Certified {
                certificate: serde_json::json!({
                    "reentrancy": {
                        "model": "final-call-graph-v1",
                        "status": "no-group-accessor-reachable-from-group-accessor",
                    },
                    "lock_recipe": {
                        "granularity": "shared-group",
                        "group": group.id,
                        "members": group.members,
                        "scope": "whole-accessor-function-v1",
                        "dynamic_audit": "lock-cycle-detection-required",
                    },
                    "accessor_functions": accessors.iter().map(|func| analysis.functions()[*func].key.clone()).collect::<Vec<_>>(),
                }),
                extra: Extra::new(),
            },
        });
    }
}

fn mutex_witness(
    kind: &str,
    symbol: Option<String>,
    site: Option<Site>,
    note: Option<String>,
) -> Witness {
    Witness {
        kind: kind.into(),
        site,
        symbol,
        note,
        extra: Extra::new(),
    }
}

fn mutex_path_witness(
    analysis: &Analysis,
    global: &str,
    path: &[(FuncId, MutexCallStep)],
) -> Witness {
    let call_path = path
        .iter()
        .map(|(caller, step)| {
            let callsite = step.callsite.map(|id| &analysis.callsites()[id]);
            serde_json::json!({
                "caller": analysis.functions()[*caller].key,
                "callee": analysis.functions()[step.callee].key,
                "callsite": callsite.map(|site| &site.key),
                "site": callsite.and_then(|site| site.loc.as_ref()).map(|loc| serde_json::json!({
                    "file": loc.file,
                    "line": loc.line,
                    "col": loc.col,
                })),
            })
        })
        .collect::<Vec<_>>();
    let first_site = path
        .iter()
        .find_map(|(_, step)| step.callsite)
        .and_then(|id| analysis.callsites()[id].loc.as_ref())
        .map(|loc| Site {
            file: loc.file.clone(),
            line: loc.line,
            col: Some(loc.col),
            function: Some(analysis.functions()[path[0].0].key.clone()),
            extra: Extra::new(),
        });
    Witness {
        kind: "mutex-reentrant-access-path".into(),
        site: first_site,
        symbol: Some(global.into()),
        note: Some("an accessor can call an accessor while holding the would-be mutex".into()),
        extra: BTreeMap::from([("call_path".into(), serde_json::json!(call_path))]),
    }
}

fn mutex_unknown_callee_witness(
    analysis: &Analysis,
    global: &str,
    path: &[(FuncId, MutexCallStep)],
    caller: FuncId,
    unknown: &MutexUnknownStep,
) -> Witness {
    let mut call_path = path
        .iter()
        .map(|(caller, step)| {
            let callsite = step.callsite.map(|id| &analysis.callsites()[id]);
            serde_json::json!({
                "caller": analysis.functions()[*caller].key,
                "callee": analysis.functions()[step.callee].key,
                "callsite": callsite.map(|site| &site.key),
            })
        })
        .collect::<Vec<_>>();
    let callsite = unknown.callsite.map(|id| &analysis.callsites()[id]);
    call_path.push(serde_json::json!({
        "caller": analysis.functions()[caller].key,
        "callee": { "unknown": unknown.reason },
        "callsite": callsite.map(|site| &site.key),
    }));
    let site = callsite.and_then(|site| site.loc.as_ref()).map(|loc| Site {
        file: loc.file.clone(),
        line: loc.line,
        col: Some(loc.col),
        function: Some(analysis.functions()[caller].key.clone()),
        extra: Extra::new(),
    });
    Witness {
        kind: "mutex-unknown-callee-reentrancy".into(),
        site,
        symbol: Some(global.into()),
        note: Some(
            "an unresolved callee reachable while holding the would-be mutex may call an accessor"
                .into(),
        ),
        extra: BTreeMap::from([("call_path".into(), serde_json::json!(call_path))]),
    }
}

fn atomic_access_recipe(
    analysis: &Analysis,
    sites: &[&pangs_api::AccessSite],
    type_evidence: Option<&pangs_pir::ScalarTypeEvidence>,
    global: &str,
) -> (Option<Vec<Value>>, Vec<(String, Witness)>) {
    if type_evidence.is_some_and(|evidence| evidence.qualifiers.is_atomic) {
        return (
            None,
            vec![(
                "source-atomic-unsupported".into(),
                atomic_witness(
                    "source-atomic-unsupported",
                    Some(global.into()),
                    None,
                    Some("source _Atomic ordering is not preserved by the current PIR".into()),
                ),
            )],
        );
    }
    let mut ordered = sites.to_vec();
    ordered.sort_by_key(|site| (site.func, site.statement_index, site.access, site.via));
    let mut failures = Vec::new();
    let mut entries = Vec::new();
    let mut consumed = vec![false; ordered.len()];

    for index in 0..ordered.len() {
        if consumed[index] {
            continue;
        }
        let site = ordered[index];
        let function = &analysis.functions()[site.func];
        let manifest_site = atomic_access_site(analysis, site);
        if site.volatile {
            failures.push((
                "volatile-access".into(),
                atomic_witness(
                    "atomic-volatile-access",
                    Some(function.key.clone()),
                    manifest_site,
                    Some("volatile C access cannot be replaced by an ordinary Rust atomic".into()),
                ),
            ));
            continue;
        }
        if site.via != pangs_api::Via::Direct {
            failures.push((
                "address-access-not-lowerable".into(),
                atomic_witness(
                    "atomic-address-access-not-lowerable",
                    Some(function.key.clone()),
                    manifest_site,
                    Some(format!("{:?} access", site.via)),
                ),
            ));
            continue;
        }
        if site.loc.is_none() || site.statement_index.is_none() {
            failures.push((
                "access-site-unmapped".into(),
                atomic_witness(
                    "atomic-access-site-unmapped",
                    Some(function.key.clone()),
                    manifest_site,
                    site.statement_index
                        .map(|value| format!("statement {value}")),
                ),
            ));
            continue;
        }

        if site.access == pangs_pir::Access::Ref {
            let pair = ((index + 1)..ordered.len()).find(|&other| {
                let candidate = ordered[other];
                !consumed[other]
                    && candidate.func == site.func
                    && candidate.access == pangs_pir::Access::Mod
                    && candidate.via == pangs_api::Via::Direct
                    && candidate.atomic_rmw.as_ref().is_some_and(|rmw| {
                        Some(rmw.reference_statement_index) == site.statement_index
                    })
            });
            if let Some(other) = pair {
                consumed[other] = true;
                let rmw = ordered[other]
                    .atomic_rmw
                    .as_ref()
                    .expect("an exact RMW pair carries operation evidence");
                entries.push(serde_json::json!({
                    "operation": atomic_rmw_operation(rmw.op),
                    "operand": rmw.operand,
                    "function": function.key,
                    "site": manifest_site,
                    "statement_indices": [
                        site.statement_index,
                        rmw.operation_statement_index,
                        ordered[other].statement_index
                    ],
                }));
                continue;
            }
        }

        if site.atomic_rmw.is_some() {
            failures.push((
                "rmw-shape-unresolved".into(),
                atomic_witness(
                    "atomic-rmw-shape-unresolved",
                    Some(function.key.clone()),
                    manifest_site,
                    Some("recognized scalar update has no matching direct global load".into()),
                ),
            ));
            continue;
        }

        let shares_source_expression_with_opposite_access = ordered.iter().any(|candidate| {
            candidate.func == site.func
                && candidate.loc == site.loc
                && candidate.access != site.access
                && candidate.atomic_rmw.is_none()
        });
        if shares_source_expression_with_opposite_access {
            failures.push((
                "rmw-shape-unclassified".into(),
                atomic_witness(
                    "atomic-rmw-shape-unclassified",
                    Some(function.key.clone()),
                    manifest_site,
                    Some(
                        "same-expression load/store lacks a proven supported scalar operation"
                            .into(),
                    ),
                ),
            ));
            continue;
        }

        entries.push(serde_json::json!({
            "operation": if site.access == pangs_pir::Access::Ref { "load" } else { "store" },
            "function": function.key,
            "site": manifest_site,
            "statement_index": site.statement_index,
        }));
    }

    if failures.is_empty() {
        (Some(entries), failures)
    } else {
        (None, failures)
    }
}

fn atomic_rmw_operation(op: pangs_pir::ScalarOp) -> &'static str {
    match op {
        pangs_pir::ScalarOp::Add => "fetch_add",
        pangs_pir::ScalarOp::Sub => "fetch_sub",
        pangs_pir::ScalarOp::And => "fetch_and",
        pangs_pir::ScalarOp::Or => "fetch_or",
        pangs_pir::ScalarOp::Xor => "fetch_xor",
    }
}

fn atomic_access_site(analysis: &Analysis, access: &pangs_api::AccessSite) -> Option<Site> {
    let loc = access.loc.as_ref()?;
    let function = &analysis.functions()[access.func];
    Some(Site {
        file: loc.file.clone(),
        line: loc.line,
        col: Some(loc.col),
        function: Some(function.key.clone()),
        extra: Extra::new(),
    })
}

fn atomic_witness(
    kind: &str,
    symbol: Option<String>,
    site: Option<Site>,
    note: Option<String>,
) -> Witness {
    Witness {
        kind: kind.into(),
        site,
        symbol,
        note,
        extra: Extra::new(),
    }
}

struct CouplingComponents {
    parent: Vec<usize>,
    size: Vec<usize>,
}

impl CouplingComponents {
    fn new(len: usize) -> Self {
        Self {
            parent: (0..len).collect(),
            size: vec![1; len],
        }
    }

    fn find(&mut self, mut index: usize) -> usize {
        while self.parent[index] != index {
            self.parent[index] = self.parent[self.parent[index]];
            index = self.parent[index];
        }
        index
    }

    fn union(&mut self, left: usize, right: usize) -> bool {
        let mut left = self.find(left);
        let mut right = self.find(right);
        if left == right {
            return false;
        }
        if self.size[left] < self.size[right] {
            std::mem::swap(&mut left, &mut right);
        }
        self.parent[right] = left;
        self.size[left] += self.size[right];
        true
    }

    fn component_size(&mut self, index: usize) -> usize {
        let root = self.find(index);
        self.size[root]
    }
}

#[derive(Clone)]
struct CertifiedGroupEvidence {
    publication_function: String,
    descent_path: Value,
    earliest: Site,
    latest: Site,
    init_functions: BTreeSet<String>,
}

struct OnceLockPairEvidence {
    sites: Vec<Site>,
    extra: Extra,
}

fn certified_group_evidence(global: &DispositionGlobal) -> Option<CertifiedGroupEvidence> {
    let Certificate::Certified { certificate, .. } = global.facts.phase_stationarity.as_ref()?
    else {
        return None;
    };
    let publication = certificate.get("publication")?;
    let publication_function = publication.get("publication_function")?.as_str()?.into();
    let descent_path = publication.get("spine_descent_path")?.clone();
    let interval = publication.get("publication_interval")?;
    let earliest = serde_json::from_value(interval.get("earliest")?.clone()).ok()?;
    let latest = serde_json::from_value(interval.get("latest")?.clone()).ok()?;
    let init_functions = certificate
        .get("init_subtree")?
        .as_array()?
        .iter()
        .filter_map(|entry| entry.get("function")?.as_str().map(str::to_owned))
        .collect();
    Some(CertifiedGroupEvidence {
        publication_function,
        descent_path,
        earliest,
        latest,
        init_functions,
    })
}

fn once_lock_pair_evidence(
    left: &CertifiedGroupEvidence,
    right: &CertifiedGroupEvidence,
) -> Option<OnceLockPairEvidence> {
    if left.publication_function != right.publication_function
        || left.descent_path != right.descent_path
    {
        return None;
    }
    let (earliest, latest) = intersect_intervals(
        (&left.earliest, &left.latest),
        (&right.earliest, &right.latest),
    )?;
    let shared_init_functions = left
        .init_functions
        .intersection(&right.init_functions)
        .cloned()
        .collect::<Vec<_>>();
    if shared_init_functions.is_empty() {
        return None;
    }
    let mut sites = vec![earliest.clone()];
    if site_cmp(&earliest, &latest) != std::cmp::Ordering::Equal {
        sites.push(latest.clone());
    }
    let extra = BTreeMap::from([
        (
            "common_interval".into(),
            serde_json::json!({"earliest": earliest, "latest": latest}),
        ),
        (
            "shared_init_functions".into(),
            serde_json::json!(shared_init_functions),
        ),
        ("spine_descent_path".into(), left.descent_path.clone()),
    ]);
    Some(OnceLockPairEvidence { sites, extra })
}

fn once_lock_pair_compatible(
    left: &CertifiedGroupEvidence,
    right: &CertifiedGroupEvidence,
) -> bool {
    left.publication_function == right.publication_function
        && left.descent_path == right.descent_path
        && intersect_intervals(
            (&left.earliest, &left.latest),
            (&right.earliest, &right.latest),
        )
        .is_some()
        && !left.init_functions.is_disjoint(&right.init_functions)
}

fn common_once_lock_support(
    analysis: &Analysis,
    members: &[Key],
    phase_by_key: &BTreeMap<Key, CertifiedGroupEvidence>,
    global_keys: &[Key],
) -> OnceLockGroupSupport {
    let unsupported = |kind: &str, member: &Key, note: &str| OnceLockGroupSupport::Unsupported {
        supported: AlwaysFalse(false),
        witness: Witness {
            kind: kind.into(),
            site: None,
            symbol: Some(member.to_string()),
            note: Some(note.into()),
            extra: Extra::new(),
        },
        extra: Extra::new(),
    };
    let Some(first_key) = members.first() else {
        unreachable!("coupling groups are nonempty")
    };
    let mut evidence = Vec::new();
    for member in members {
        if global_keys.binary_search(member).is_err() {
            return unsupported(
                "once-lock-group-member-missing",
                member,
                "group member has no disposition global record",
            );
        }
        let Some(member_evidence) = phase_by_key.get(member) else {
            return unsupported(
                "phase-stationarity-not-certified",
                member,
                "common publication support requires every member certificate",
            );
        };
        evidence.push((member, member_evidence));
    }
    let (_, first) = evidence[0];
    for (member, candidate) in evidence.iter().skip(1) {
        if candidate.publication_function != first.publication_function {
            return unsupported(
                "once-lock-publication-function-mismatch",
                member,
                "member publication functions differ",
            );
        }
        if candidate.descent_path != first.descent_path {
            return unsupported(
                "once-lock-spine-path-mismatch",
                member,
                "member spine descent paths differ",
            );
        }
    }
    let mut earliest = first.earliest.clone();
    let mut latest = first.latest.clone();
    for (member, candidate) in evidence.iter().skip(1) {
        let Some((next_earliest, next_latest)) = intersect_intervals(
            (&earliest, &latest),
            (&candidate.earliest, &candidate.latest),
        ) else {
            return unsupported(
                "once-lock-publication-interval-disjoint",
                member,
                "member publication intervals have no common insertion point",
            );
        };
        earliest = next_earliest;
        latest = next_latest;
    }
    let Some(function) = analysis.lookup_func(&first.publication_function) else {
        return unsupported(
            "once-lock-publication-function-unkeyed",
            first_key,
            "publication function is absent from the final function table",
        );
    };
    let info = &analysis.functions()[function];
    let Some(file) = info.file.as_deref() else {
        return unsupported(
            "once-lock-publication-function-unkeyed",
            first_key,
            "publication function lacks a normalized source path",
        );
    };
    let Ok(publication_function) = Key::new(file, info.key.strip_prefix('@').unwrap_or(&info.key))
    else {
        return unsupported(
            "once-lock-publication-function-unkeyed",
            first_key,
            "publication function cannot be assigned a stable key",
        );
    };
    OnceLockGroupSupport::Supported {
        supported: AlwaysTrue(true),
        publication_function,
        common_interval: CommonInterval {
            earliest: earliest.clone(),
            latest,
            extra: Extra::new(),
        },
        common_p: earliest,
        extra: Extra::new(),
    }
}

fn intersect_intervals(left: (&Site, &Site), right: (&Site, &Site)) -> Option<(Site, Site)> {
    let earliest = if site_cmp(left.0, right.0).is_lt() {
        right.0
    } else {
        left.0
    };
    let latest = if site_cmp(left.1, right.1).is_gt() {
        right.1
    } else {
        left.1
    };
    (site_cmp(earliest, latest).is_le()).then(|| (earliest.clone(), latest.clone()))
}

fn site_cmp(left: &Site, right: &Site) -> std::cmp::Ordering {
    (&left.file, left.line, left.col.unwrap_or(0)).cmp(&(
        &right.file,
        right.line,
        right.col.unwrap_or(0),
    ))
}

fn fnv1a32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c9dc5, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x01000193)
    })
}

fn coupling_group_id(members: &[Key]) -> String {
    let smallest = members
        .iter()
        .min()
        .expect("coupling group ids require at least one member");
    format!("grp-{:08x}", fnv1a32(smallest.to_string().as_bytes()))
}

fn evidenced(value: bool, polarity: bool, witness: Option<Witness>) -> EvidencedBool {
    debug_assert_eq!(witness.is_some(), value == polarity);
    EvidencedBool {
        value,
        witness,
        extra: Extra::new(),
    }
}

fn word_sized_scalar(
    info: &pangs_api::GlobalInfo,
    target: &pangs_pir::TargetInfo,
) -> WordSizedScalar {
    let class = info.scalar_class.map(|class| match class {
        pangs_pir::ScalarTypeClass::Integer => ScalarClass::Integer,
        pangs_pir::ScalarTypeClass::Boolean => ScalarClass::Boolean,
        pangs_pir::ScalarTypeClass::Enum => ScalarClass::Enum,
        pangs_pir::ScalarTypeClass::Pointer => ScalarClass::Pointer,
    });
    let signedness_known =
        !matches!(class, Some(ScalarClass::Integer | ScalarClass::Enum)) || info.signed.is_some();
    let value = info.type_spelling.is_some()
        && info
            .size_bits
            .is_some_and(|width| width != 0 && target.supported_atomic_widths.contains(&width))
        && info.align_bits == info.size_bits
        && class.is_some()
        && signedness_known;

    WordSizedScalar {
        value,
        type_spelling: value.then(|| info.type_spelling.clone()).flatten(),
        size_bits: value.then_some(info.size_bits).flatten(),
        class: value.then_some(class).flatten(),
        signed: value.then_some(info.signed).flatten(),
        extra: Extra::new(),
    }
}

struct DispositionFactRows<'a> {
    written: Vec<Option<&'a ModRef>>,
    escape: Vec<Option<&'a ModRef>>,
    access_failure: Vec<Option<&'a ModRef>>,
    bounded_indirect: Vec<Option<&'a ModRef>>,
    violation: Vec<Option<Witness>>,
    violation_diagnostics: Vec<Vec<ViolationRelevanceDiagnostic>>,
    localization: Vec<Option<Localization>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ViolationRelevance {
    AddressRelevant,
    AccessShapeRelevant,
    #[allow(dead_code)] // Reserved until a retained load-value path proves this class.
    ValueOnly,
    Unrelated,
    Unresolved,
}

impl ViolationRelevance {
    fn is_hard(self) -> bool {
        matches!(
            self,
            Self::AddressRelevant | Self::AccessShapeRelevant | Self::Unresolved
        )
    }

    fn witness_kind(self) -> &'static str {
        match self {
            Self::AddressRelevant => "violation-address-relevant",
            Self::AccessShapeRelevant => "violation-access-shape-relevant",
            Self::ValueOnly => "violation-value-only",
            Self::Unrelated => "violation-unrelated",
            Self::Unresolved => "violation-relevance-unresolved",
        }
    }
}

impl From<ViolationRelevance> for ManifestViolationRelevance {
    fn from(value: ViolationRelevance) -> Self {
        match value {
            ViolationRelevance::AddressRelevant => Self::AddressRelevant,
            ViolationRelevance::AccessShapeRelevant => Self::AccessShapeRelevant,
            ViolationRelevance::ValueOnly => Self::ValueOnly,
            ViolationRelevance::Unrelated => Self::Unrelated,
            ViolationRelevance::Unresolved => Self::Unresolved,
        }
    }
}

impl<'a> DispositionFactRows<'a> {
    fn new(analysis: &'a Analysis) -> Self {
        let global_count = analysis.globals().len();
        let mut written = vec![None; global_count];
        let mut escape = vec![None; global_count];
        let mut access_failure = vec![None; global_count];
        let mut bounded_indirect = vec![None; global_count];
        for row in analysis.modrefs() {
            match row.global {
                GlobalTarget::Name(global) => {
                    let index = global.0 as usize;
                    if row.access == pangs_pir::Access::Mod && written[index].is_none() {
                        written[index] = Some(row);
                    }
                    if row.via != pangs_api::Via::Direct {
                        bounded_indirect[index].get_or_insert(row);
                    }
                }
                GlobalTarget::Unknown(_) => match analysis.affected_globals(row) {
                    AffectedGlobals::Finite(globals) => {
                        for global in globals {
                            let index = global.0 as usize;
                            escape[index].get_or_insert(row);
                            bounded_indirect[index].get_or_insert(row);
                        }
                    }
                    AffectedGlobals::ModuleWide => {
                        for index in 0..global_count {
                            escape[index].get_or_insert(row);
                            access_failure[index].get_or_insert(row);
                        }
                    }
                },
            }
        }
        // Findings are function-scoped.  Building these two indexes once avoids scanning every
        // mod/ref (and every access site) again for each finding.  On large linked programs the
        // old O(findings * modrefs) walk dominated disposition assembly.
        let mut modrefs_by_function = vec![Vec::new(); analysis.functions().len()];
        for row in analysis.modrefs() {
            modrefs_by_function[row.func.0 as usize].push(row);
        }
        let mut indirect_access_sites_by_function =
            vec![Vec::<&pangs_api::AccessSite>::new(); analysis.functions().len()];
        for site in analysis.access_sites() {
            if site.via != pangs_api::Via::Direct && site.loc.is_some() {
                indirect_access_sites_by_function[site.func.0 as usize].push(site);
            }
        }
        let finding_functions = analysis
            .audit_findings()
            .iter()
            .filter_map(|finding| finding.function)
            .collect::<BTreeSet<_>>();
        // Candidate rows depend only on the finding's function. Large programs often have
        // several findings in the same high-fanout function, so expanding retained target sets
        // once per function avoids rebuilding an identical map for every finding.
        let mut rows_by_global_by_function = vec![None; analysis.functions().len()];
        for function in finding_functions {
            let mut rows_by_global = BTreeMap::<GlobalId, Vec<&ModRef>>::new();
            for row in &modrefs_by_function[function.0 as usize] {
                match analysis.affected_globals(row) {
                    AffectedGlobals::Finite(globals) => {
                        for &global in globals {
                            rows_by_global.entry(global).or_default().push(row);
                        }
                    }
                    AffectedGlobals::ModuleWide => {
                        // Module-wide rows establish boundedness failure, but same-function
                        // co-occurrence alone is not a relevance proposal. Hard relevance for
                        // such a row is already fail-closed through access_set_complete.
                    }
                }
            }
            rows_by_global_by_function[function.0 as usize] = Some(rows_by_global);
        }

        let mut violation = vec![None; global_count];
        let mut violation_diagnostics = vec![Vec::new(); global_count];
        for finding in analysis.audit_findings() {
            let Some(function) = finding.function else {
                continue;
            };
            let rows_by_global = rows_by_global_by_function[function.0 as usize]
                .as_ref()
                .expect("finding-bearing function has a relevance index");
            let affected_nodes = violation_affected_nodes(analysis, finding, function);
            for (&global, rows) in rows_by_global {
                let relevance = classify_violation_relevance_indexed(
                    analysis,
                    finding,
                    global,
                    rows,
                    Some(&indirect_access_sites_by_function[function.0 as usize]),
                    &affected_nodes,
                );
                let witness =
                    violation_relevance_witness(analysis, finding, function, global, relevance);
                let index = global.0 as usize;
                if relevance.is_hard() && violation[index].is_none() {
                    violation[index] = Some(witness.clone());
                }
                violation_diagnostics[index].push(ViolationRelevanceDiagnostic {
                    classification: relevance.into(),
                    finding_kind: finding.kind.clone(),
                    witness,
                });
            }
        }
        let localization = localization_index(analysis);
        Self {
            written,
            escape,
            access_failure,
            bounded_indirect,
            violation,
            violation_diagnostics,
            localization,
        }
    }
}

#[cfg(test)]
fn classify_violation_relevance(
    analysis: &Analysis,
    finding: &pangs_api::Finding,
    function: FuncId,
    global: GlobalId,
    rows: &[&ModRef],
) -> ViolationRelevance {
    let indirect_sites = analysis
        .access_sites_for_global(global)
        .filter(|site| site.func == function && site.via != pangs_api::Via::Direct)
        .collect::<Vec<_>>();
    let affected_nodes = violation_affected_nodes(analysis, finding, function);
    classify_violation_relevance_indexed(
        analysis,
        finding,
        global,
        rows,
        Some(&indirect_sites),
        &affected_nodes,
    )
}

fn violation_affected_nodes(
    analysis: &Analysis,
    finding: &pangs_api::Finding,
    function: FuncId,
) -> BTreeSet<String> {
    let function_key = &analysis.functions()[function].key;
    finding
        .affected
        .iter()
        .filter_map(|affected| affected.strip_prefix("value:"))
        .flat_map(|value| [value.to_owned(), format!("val:{function_key}:{value}")])
        .collect()
}

fn classify_violation_relevance_indexed(
    analysis: &Analysis,
    finding: &pangs_api::Finding,
    global: GlobalId,
    rows: &[&ModRef],
    indirect_sites: Option<&[&pangs_api::AccessSite]>,
    affected_nodes: &BTreeSet<String>,
) -> ViolationRelevance {
    let global_key = &analysis.globals()[global].key;
    if finding.affected.iter().any(|affected| {
        affected
            .strip_prefix("value:")
            .or_else(|| affected.strip_prefix("global:"))
            .is_some_and(|value| value == global_key)
    }) {
        return ViolationRelevance::AddressRelevant;
    }

    if rows.iter().any(|row| {
        row.address_node
            .as_ref()
            .is_some_and(|node| affected_nodes.contains(node))
    }) {
        return ViolationRelevance::AddressRelevant;
    }

    let flow_is_disjoint = match &finding.global_flow {
        pangs_api::AuditGlobalFlow::Finite(globals) if globals.contains(&global) => {
            return ViolationRelevance::AddressRelevant;
        }
        pangs_api::AuditGlobalFlow::Finite(_) => true,
        pangs_api::AuditGlobalFlow::ModuleWide | pangs_api::AuditGlobalFlow::NotComputed => false,
    };

    let has_indirect = rows.iter().any(|row| {
        row.via != pangs_api::Via::Direct || matches!(row.global, GlobalTarget::Unknown(_))
    });
    if has_indirect
        && finding
            .file
            .as_ref()
            .zip(finding.line)
            .is_some_and(|(file, line)| {
                indirect_sites.is_some_and(|sites| {
                    sites.iter().any(|site| {
                        site.affects(global)
                            && site
                                .loc
                                .as_ref()
                                .is_some_and(|loc| loc.file == *file && loc.line == line)
                    })
                })
            })
    {
        return ViolationRelevance::AccessShapeRelevant;
    }
    if has_indirect && !(flow_is_disjoint && modeled_pointer_only_finding(&finding.kind)) {
        return ViolationRelevance::Unresolved;
    }

    if modeled_pointer_only_finding(&finding.kind) {
        ViolationRelevance::Unrelated
    } else {
        ViolationRelevance::Unresolved
    }
}

fn modeled_pointer_only_finding(kind: &str) -> bool {
    matches!(
        kind,
        "fnptr_ptrtoint"
            | "fnptr_inttoptr"
            | "fnptr_varargs_external"
            | "fnptr_varargs_indirect"
            | "fnptr_varargs_internal_unmodeled"
            | "memcpy_fnptr_aggregate"
            | "memset_fnptr_aggregate"
            | "dlopen_dlsym"
            | "setjmp_longjmp"
    )
}

fn violation_relevance_witness(
    analysis: &Analysis,
    finding: &pangs_api::Finding,
    function: FuncId,
    global: GlobalId,
    relevance: ViolationRelevance,
) -> Witness {
    Witness {
        kind: relevance.witness_kind().into(),
        site: finding
            .file
            .as_ref()
            .zip(finding.line)
            .map(|(file, line)| Site {
                file: file.clone(),
                line,
                col: None,
                function: Some(analysis.functions()[function].key.clone()),
                extra: Extra::new(),
            }),
        symbol: Some(analysis.globals()[global].key.clone()),
        note: Some(finding.kind.clone()),
        extra: Extra::new(),
    }
}

fn omega_escape_witness(
    analysis: &Analysis,
    key: &Key,
    info: &pangs_api::GlobalInfo,
    fallback: Option<&ModRef>,
) -> Witness {
    if let Some(source) = &info.escape_witness {
        return escape_source_witness(analysis, key, source);
    }
    if let Some(row) = fallback {
        let mut witness =
            function_witness(analysis, row.func, "external-escape", row.witness.clone());
        witness.symbol = Some(key.to_string());
        return witness;
    }
    Witness {
        kind: "external-escape".into(),
        site: None,
        symbol: Some(key.to_string()),
        note: Some("analysis escape class reaches the external boundary".into()),
        extra: Extra::new(),
    }
}

fn escape_source_witness(analysis: &Analysis, key: &Key, source: &str) -> Witness {
    let site = source
        .strip_prefix("external-call:")
        .or_else(|| source.strip_prefix("vararg-call:"))
        .and_then(|callsite| {
            let (function, location) = callsite.split_once('@')?;
            let location = location.rsplit_once('#')?.0;
            let mut pieces = location.rsplitn(3, ':');
            let col = pieces.next()?.parse().ok()?;
            let line = pieces.next()?.parse().ok()?;
            let file = pieces.next()?.to_owned();
            let function = analysis
                .lookup_func(function)
                .and_then(|id| {
                    let info = &analysis.functions()[id];
                    info.file.as_deref().and_then(|file| {
                        Key::new(file, info.key.strip_prefix('@').unwrap_or(&info.key)).ok()
                    })
                })
                .map(|key| key.to_string());
            Some(Site {
                file,
                line,
                col: Some(col),
                function,
                extra: Extra::new(),
            })
        });
    Witness {
        kind: "external-escape".into(),
        site,
        symbol: Some(key.to_string()),
        note: Some(source.into()),
        extra: Extra::new(),
    }
}

fn written_witness(
    analysis: &Analysis,
    info: &pangs_api::GlobalInfo,
    escape_witness: Option<&Witness>,
    write_row: Option<&ModRef>,
) -> Witness {
    if let Some(row) = write_row {
        return function_witness(analysis, row.func, "write-site", row.witness.clone());
    }
    if let Some(witness) = escape_witness {
        return witness.clone();
    }
    Witness {
        kind: if info.exported {
            "external-name-reachability"
        } else {
            "write-site"
        }
        .into(),
        site: info.file.as_ref().zip(info.line).map(|(file, line)| Site {
            file: file.clone(),
            line,
            col: None,
            function: None,
            extra: Extra::new(),
        }),
        symbol: Some(info.key.clone()),
        note: Some(if info.exported {
            "exported storage may be written by an external library client".into()
        } else {
            "write is attributable to global initialization or synthesized module code".into()
        }),
        extra: Extra::new(),
    }
}

fn function_witness(
    analysis: &Analysis,
    function: FuncId,
    kind: &str,
    note: Option<String>,
) -> Witness {
    let info = &analysis.functions()[function];
    let qualified = info.file.as_deref().and_then(|file| {
        Key::new(file, info.key.strip_prefix('@').unwrap_or(&info.key))
            .ok()
            .map(|key| key.to_string())
    });
    let symbol = qualified.clone().unwrap_or_else(|| info.key.clone());
    Witness {
        kind: kind.into(),
        site: info.file.as_ref().zip(info.line).map(|(file, line)| Site {
            file: file.clone(),
            line,
            col: None,
            function: Some(symbol.clone()),
            extra: Extra::new(),
        }),
        symbol: Some(symbol),
        note,
        extra: Extra::new(),
    }
}

fn initializer_address_witness(
    analysis: &Analysis,
    localized_global: GlobalId,
    initializer: &str,
    kind: &str,
) -> Witness {
    let owner = analysis
        .globals()
        .iter()
        .find(|global| global.key == initializer);
    let target = &analysis.globals()[localized_global].key;
    Witness {
        kind: kind.into(),
        site: owner.and_then(|info| {
            info.file.as_ref().zip(info.line).map(|(file, line)| Site {
                file: file.clone(),
                line,
                col: None,
                function: None,
                extra: Extra::new(),
            })
        }),
        symbol: Some(initializer.to_string()),
        note: Some(format!(
            "static initializer for {initializer} retains the address of {target}"
        )),
        extra: Extra::new(),
    }
}

fn access_set_failure(
    analysis: &Analysis,
    llvm_name: &str,
    omega: Option<&Witness>,
    mode: BuildMode,
    exported: bool,
    failure_row: Option<&ModRef>,
) -> Option<Witness> {
    if let Some(row) = failure_row {
        return Some(function_witness(
            analysis,
            row.func,
            "module-wide-access",
            row.witness.clone(),
        ));
    }
    if let Some(witness) = omega {
        return Some(witness.clone());
    }
    if mode == BuildMode::Library && exported {
        return Some(Witness {
            kind: "external-escape".into(),
            site: None,
            symbol: Some(llvm_name.into()),
            note: Some("global is reachable by name from external library clients".into()),
            extra: Extra::new(),
        });
    }
    None
}

fn localization_index(analysis: &Analysis) -> Vec<Option<Localization>> {
    let mut out = vec![None; analysis.globals().len()];
    let plan = analysis.context_rewrite_plan();
    for field in &plan.fields {
        let blockers = field
            .blockers
            .iter()
            .map(|blocker| LocalizationBlocker {
                code: blocker.kind.clone(),
                witness: if let Some(initializer) = &blocker.initializer {
                    initializer_address_witness(analysis, field.global, initializer, &blocker.kind)
                } else {
                    function_witness(
                        analysis,
                        blocker
                            .function
                            .expect("function rewrite blocker must name a function"),
                        &blocker.kind,
                        blocker
                            .callsite
                            .map(|site| analysis.callsites()[site].key.clone()),
                    )
                },
                extra: Extra::new(),
            })
            .collect::<Vec<_>>();
        out[field.global.0 as usize] = Some(Localization {
            component: plan.id.clone(),
            verdict: if blockers.is_empty() {
                LocalizationVerdict::Ok
            } else {
                LocalizationVerdict::Blocked
            },
            blockers,
            extra: Extra::new(),
        });
    }
    out
}

pub fn validate_export_dir(outdir: &Path) -> Result<()> {
    let json_files = [
        "manifest.json",
        "components.json",
        "metrics.json",
        "functions.jsonl",
        "globals.jsonl",
        "callgraph.jsonl",
        "modref.jsonl",
        "stationarity.jsonl",
        "audit.jsonl",
    ];
    for name in json_files {
        let path = outdir.join(name);
        let schema_json = load_schema_for_artifact(name)?;
        let schema_json = Box::leak(Box::new(schema_json));
        let schema = JSONSchema::compile(schema_json)
            .with_context(|| format!("compile schema for {name}"))?;
        if name.ends_with(".jsonl") {
            let file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
            for (line_no, line) in BufReader::new(file).lines().enumerate() {
                let line = line?;
                if !line.trim().is_empty() {
                    let value = serde_json::from_str::<Value>(&line).with_context(|| {
                        format!("parse {} line {}", path.display(), line_no + 1)
                    })?;
                    validate_value_against_schema(
                        &schema,
                        &value,
                        &format!("{} line {}", path.display(), line_no + 1),
                    )?;
                }
            }
        } else {
            let text =
                fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
            let value = serde_json::from_str::<Value>(&text)
                .with_context(|| format!("parse {}", path.display()))?;
            validate_value_against_schema(&schema, &value, &path.display().to_string())?;
        }
    }
    Ok(())
}

fn load_schema_for_artifact(name: &str) -> Result<Value> {
    let schema_name = name.replace(".jsonl", ".schema.json");
    let schema_name = if schema_name == "components.json" || schema_name == "metrics.json" {
        schema_name.replace(".json", ".schema.json")
    } else if schema_name == "manifest.json" {
        "manifest.schema.json".to_string()
    } else {
        schema_name
    };
    let path = schema_dir().join(schema_name);
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str::<Value>(&text).with_context(|| format!("parse {}", path.display()))
}

fn validate_value_against_schema(schema: &JSONSchema, value: &Value, label: &str) -> Result<()> {
    schema.validate(value).map_err(|errors| {
        let details = errors
            .map(|error| format!("{} at {}", error, error.instance_path))
            .collect::<Vec<_>>()
            .join("; ");
        anyhow::anyhow!("schema validation failed for {label}: {details}")
    })
}

fn schema_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas")
        .to_path_buf()
}

pub fn report(outdir: &Path) -> Result<String> {
    let metrics_path = outdir.join("metrics.json");
    let metrics: pangs_api::Metrics = serde_json::from_str(
        &fs::read_to_string(&metrics_path)
            .with_context(|| format!("read {}", metrics_path.display()))?,
    )?;
    let manifest_path = outdir.join("manifest.json");
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(&manifest_path)
            .with_context(|| format!("read {}", manifest_path.display()))?,
    )?;
    let wall_ms = manifest["wall_ms"].as_u64().unwrap_or(0);
    let component_summary = component_summary(outdir)?;
    let callgraph_summary = jsonl_histogram(outdir, "callgraph.jsonl", &["tier"])?;
    let stationarity_summary = jsonl_histogram(outdir, "stationarity.jsonl", &["reason"])?;
    let audit_kind_summary = jsonl_histogram(outdir, "audit.jsonl", &["kind"])?;
    let audit_effect_summary = jsonl_histogram(outdir, "audit.jsonl", &["effect"])?;
    Ok(format!(
        "functions: {}\nglobals: {}\ncall edges: {}\nicalls by tier: simple={} (b1_initval={}, b2_simple={}) andersen={} steens={} fsa={} unknown={}\ncall edges by tier: {}\nconfined functions: {}\ninitval complete globals: {}\ninitval-stable globals: {}\nstationarity reasons: {}\noversize fallbacks: {} max_size={}\naudit findings: {}\naudit kinds: {}\naudit effects: {}\nmutable globals rewritable: {}/{}\ncomponent sizes: {}\nlargest frozen components: {}\ncomponent taints: {}\ncomponent blockers: {}\npipeline wall: {} ms\nanalysis wall: {} us\nsetup scan: {} us\npreanalysis: {} us\npag build: {} us\nsolve: {} us\nsolver postprocess: {} us\npointer modref: {} us\ncallgraph dedup: {} us\nmodref dedup: {} us\nstationarity: {} us\ninitval reapply: {} us\ntransitive modref: {} us\nfindings dedup: {} us\ncomponents: {} us\nmetrics bookkeeping: {} us\n",
        metrics.functions,
        metrics.globals,
        metrics.call_edges,
        metrics.icalls_simple,
        metrics.icalls_b1_initval,
        metrics.icalls_b2_simple,
        metrics.icalls_andersen,
        metrics.icalls_steens,
        metrics.icalls_fsa,
        metrics.icalls_unknown,
        format_histogram(&callgraph_summary),
        metrics.confined_functions,
        metrics.globals_with_complete_initval,
        metrics.initval_stable_globals,
        format_histogram(&stationarity_summary),
        metrics.oversize_fallbacks,
        metrics.oversize_fallback_max_size,
        metrics.audit_findings,
        format_histogram(&audit_kind_summary),
        format_histogram(&audit_effect_summary),
        metrics.in_rewritable_components,
        metrics.mutable_globals_total,
        component_summary.sizes,
        component_summary.largest_frozen,
        format_histogram(&component_summary.taints),
        component_summary.blockers,
        wall_ms,
        metrics.analysis_wall_us,
        metrics.setup_scan_us,
        metrics.preanalysis_us,
        metrics.pag_build_us,
        metrics.solve_us,
        metrics.solver_postprocess_us,
        metrics.pointer_modref_us,
        metrics.callgraph_dedup_us,
        metrics.modref_dedup_us,
        metrics.stationarity_us,
        metrics.initval_reapply_us,
        metrics.transitive_modref_us,
        metrics.findings_dedup_us,
        metrics.components_us,
        metrics.metrics_bookkeeping_us,
    ))
}

#[derive(Debug, Default)]
struct ComponentSummary {
    sizes: String,
    largest_frozen: String,
    taints: BTreeMap<String, usize>,
    blockers: String,
}

fn component_summary(outdir: &Path) -> Result<ComponentSummary> {
    let path = outdir.join("components.json");
    let value: Value = serde_json::from_str(
        &fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?,
    )
    .with_context(|| format!("parse {}", path.display()))?;
    let components = value["components"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("components.json missing components array"))?;

    let mut sizes = Vec::new();
    let mut frozen = Vec::new();
    let mut taints = BTreeMap::new();
    let call_edges = read_jsonl_values(outdir, "callgraph.jsonl")?;
    let modrefs = read_jsonl_values(outdir, "modref.jsonl")?;
    let audits = read_jsonl_values(outdir, "audit.jsonl")?;

    for component in components {
        let id = component["id"].as_str().unwrap_or("<unknown>").to_string();
        let members = component["members"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|member| member.as_str().map(ToOwned::to_owned))
            .collect::<BTreeSet<_>>();
        let mutable_globals = component["mutable_globals"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|global| global.as_str().map(ToOwned::to_owned))
            .collect::<BTreeSet<_>>();
        let member_count = members.len();
        let mutable_count = mutable_globals.len();
        let taint_values = component["taint"].as_array().cloned().unwrap_or_default();
        let taint_kinds = taint_values
            .iter()
            .filter_map(|taint| taint["kind"].as_str())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();

        sizes.push(member_count);
        for kind in &taint_kinds {
            *taints.entry(kind.clone()).or_insert(0) += 1;
        }
        if component["frozen"].as_bool().unwrap_or(false) {
            frozen.push(FrozenComponent {
                member_count,
                mutable_count,
                id,
                members,
                mutable_globals,
                taint_kinds,
            });
        }
    }

    sizes.sort_unstable();
    frozen.sort_by(|left, right| {
        right
            .member_count
            .cmp(&left.member_count)
            .then_with(|| left.id.cmp(&right.id))
    });

    let sizes = if sizes.is_empty() {
        "count=0 p50=0 p95=0 max=0".to_string()
    } else {
        format!(
            "count={} p50={} p95={} max={}",
            sizes.len(),
            percentile(&sizes, 50),
            percentile(&sizes, 95),
            sizes.last().copied().unwrap_or(0)
        )
    };

    let largest_frozen = if frozen.is_empty() {
        "none".to_string()
    } else {
        frozen
            .iter()
            .take(5)
            .map(|component| {
                let taints = if component.taint_kinds.is_empty() {
                    "none".to_string()
                } else {
                    format_histogram(&histogram_from_strings(&component.taint_kinds))
                };
                format!(
                    "{}(members={}, mutable_globals={}, taints={taints})",
                    component.id, component.member_count, component.mutable_count
                )
            })
            .collect::<Vec<_>>()
            .join("; ")
    };
    let blockers = format_component_blockers(&frozen, &call_edges, &modrefs, &audits);

    Ok(ComponentSummary {
        sizes,
        largest_frozen,
        taints,
        blockers,
    })
}

#[derive(Debug)]
struct FrozenComponent {
    id: String,
    member_count: usize,
    mutable_count: usize,
    members: BTreeSet<String>,
    mutable_globals: BTreeSet<String>,
    taint_kinds: Vec<String>,
}

fn format_component_blockers(
    frozen: &[FrozenComponent],
    call_edges: &[Value],
    modrefs: &[Value],
    audits: &[Value],
) -> String {
    if frozen.is_empty() {
        return "none".to_string();
    }

    frozen
        .iter()
        .take(5)
        .map(|component| {
            let mut incoming_indirect = BTreeMap::new();
            let mut outgoing_indirect = BTreeMap::new();
            let mut unknown_callees = 0usize;
            let mut unknown_callers = 0usize;

            for edge in call_edges {
                if edge["kind"].as_str() != Some("indirect") {
                    continue;
                }
                let tier = edge["tier"].as_str().unwrap_or("<missing>");
                let caller = endpoint_func(&edge["caller"]);
                let callee = endpoint_func(&edge["callee"]);
                let caller_unknown = endpoint_unknown(&edge["caller"]).is_some();
                let callee_unknown = endpoint_unknown(&edge["callee"]).is_some();

                if caller
                    .as_deref()
                    .is_some_and(|func| component.members.contains(func))
                {
                    *outgoing_indirect.entry(tier.to_string()).or_insert(0) += 1;
                    if callee_unknown {
                        unknown_callees += 1;
                    }
                }
                if callee
                    .as_deref()
                    .is_some_and(|func| component.members.contains(func))
                {
                    *incoming_indirect.entry(tier.to_string()).or_insert(0) += 1;
                    if caller_unknown {
                        unknown_callers += 1;
                    }
                }
            }

            let mut unknown_modrefs = 0usize;
            for row in modrefs {
                let func_touches_component = row["func"]
                    .as_str()
                    .is_some_and(|func| component.members.contains(func));
                let global_touches_component = row["global"]["name"]
                    .as_str()
                    .is_some_and(|global| component.mutable_globals.contains(global));
                let unknown_global = row["global"]["unknown"].as_str().is_some();
                if (func_touches_component || global_touches_component) && unknown_global {
                    unknown_modrefs += 1;
                }
            }

            let mut audit_kinds = BTreeMap::new();
            for audit in audits {
                let Some(affected) = audit["affected"].as_array() else {
                    continue;
                };
                let touches_component = affected.iter().any(|item| {
                    let Some(affected) = item.as_str() else {
                        return false;
                    };
                    affected
                        .strip_prefix("function:")
                        .is_some_and(|func| component.members.contains(func))
                        || affected
                            .strip_prefix("global:")
                            .is_some_and(|global| component.mutable_globals.contains(global))
                });
                if touches_component {
                    let kind = audit["kind"].as_str().unwrap_or("<missing>");
                    *audit_kinds.entry(kind.to_string()).or_insert(0) += 1;
                }
            }

            format!(
                "{}(out_indirect={}, in_indirect={}, unknown_callees={}, unknown_callers={}, unknown_modrefs={}, audits={})",
                component.id,
                format_histogram(&outgoing_indirect),
                format_histogram(&incoming_indirect),
                unknown_callees,
                unknown_callers,
                unknown_modrefs,
                format_histogram(&audit_kinds)
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn endpoint_func(endpoint: &Value) -> Option<String> {
    endpoint["func"].as_str().map(ToOwned::to_owned)
}

fn endpoint_unknown(endpoint: &Value) -> Option<String> {
    endpoint["unknown"].as_str().map(ToOwned::to_owned)
}

fn jsonl_histogram(
    outdir: &Path,
    filename: &str,
    field_path: &[&str],
) -> Result<BTreeMap<String, usize>> {
    let values = read_jsonl_values(outdir, filename)?;
    let mut histogram = BTreeMap::new();
    for value in &values {
        let key = field_path
            .iter()
            .try_fold(value, |current, field| current.get(*field))
            .and_then(Value::as_str)
            .unwrap_or("<missing>");
        *histogram.entry(key.to_string()).or_insert(0) += 1;
    }
    Ok(histogram)
}

fn read_jsonl_values(outdir: &Path, filename: &str) -> Result<Vec<Value>> {
    let path = outdir.join(filename);
    let file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
    let mut values = Vec::new();
    for (line_no, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let value = serde_json::from_str::<Value>(&line)
            .with_context(|| format!("parse {} line {}", path.display(), line_no + 1))?;
        values.push(value);
    }
    Ok(values)
}

fn format_histogram(histogram: &BTreeMap<String, usize>) -> String {
    if histogram.is_empty() {
        return "none".to_string();
    }
    histogram
        .iter()
        .map(|(key, count)| format!("{key}={count}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn histogram_from_strings(values: &[String]) -> BTreeMap<String, usize> {
    let mut histogram = BTreeMap::new();
    for value in values {
        *histogram.entry(value.clone()).or_insert(0) += 1;
    }
    histogram
}

fn percentile(sorted: &[usize], percentile: usize) -> usize {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((sorted.len() - 1) * percentile).div_ceil(100);
    sorted[rank]
}

#[derive(Serialize)]
struct Manifest<'a> {
    schema_version: u32,
    pangs_git: String,
    llvm_version: String,
    input_path: String,
    input_sha256: String,
    opts: &'a Opts,
    files: Vec<FileRecord>,
    wall_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
struct FileRecord {
    name: String,
    records: usize,
    sha256: String,
}

#[derive(Serialize)]
struct FunctionRecord<'a> {
    key: &'a str,
    file: &'a Option<String>,
    line: Option<u32>,
    external: bool,
    exported: bool,
    address_taken: bool,
    vararg: bool,
    sig: &'a str,
}

impl<'a> From<&'a pangs_api::FuncInfo> for FunctionRecord<'a> {
    fn from(info: &'a pangs_api::FuncInfo) -> Self {
        Self {
            key: &info.key,
            file: &info.file,
            line: info.line,
            external: info.external,
            exported: info.exported,
            address_taken: info.address_taken,
            vararg: info.vararg,
            sig: &info.sig,
        }
    }
}

#[derive(Serialize)]
struct GlobalRecord<'a> {
    key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    synthetic_kind: &'a Option<String>,
    file: &'a Option<String>,
    line: Option<u32>,
    is_const: bool,
    never_written: bool,
    escape: pangs_api::EscapeStatus,
    mutable: bool,
    initval_stable: bool,
}

impl<'a> From<&'a pangs_api::GlobalInfo> for GlobalRecord<'a> {
    fn from(info: &'a pangs_api::GlobalInfo) -> Self {
        Self {
            key: &info.key,
            synthetic_kind: &info.synthetic_kind,
            file: &info.file,
            line: info.line,
            is_const: info.is_const,
            never_written: info.never_written,
            escape: info.escape,
            mutable: info.mutable,
            initval_stable: info.initval_stable,
        }
    }
}

#[derive(Serialize)]
struct CallEdgeRecord {
    caller: Endpoint,
    callsite: Option<String>,
    callee: Endpoint,
    kind: pangs_api::CallKind,
    tier: pangs_api::Tier,
}

impl CallEdgeRecord {
    fn from_edge(edge: &CallEdge, analysis: &Analysis) -> Self {
        Self {
            caller: match &edge.caller {
                Caller::Func(id) => Endpoint::Func {
                    func: func_key(analysis, *id),
                },
                Caller::Unknown(reason) => Endpoint::Unknown {
                    unknown: reason.clone(),
                },
            },
            callsite: edge.callsite.map(|id| analysis.callsites()[id].key.clone()),
            callee: match &edge.callee {
                Callee::Func(id) => Endpoint::Func {
                    func: func_key(analysis, *id),
                },
                Callee::Unknown(reason) => Endpoint::Unknown {
                    unknown: reason.clone(),
                },
            },
            kind: edge.kind,
            tier: edge.tier,
        }
    }
}

#[derive(Serialize)]
#[serde(untagged)]
enum Endpoint {
    Func { func: String },
    Unknown { unknown: String },
}

#[derive(Serialize)]
struct ModRefRecord {
    func: String,
    global: GlobalRecordTarget,
    access: pangs_pir::Access,
    via: pangs_api::Via,
    witness: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address_node: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pointee_globals: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    candidate_scope: Option<CandidateScope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pointee_global_count: Option<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pointee_global_sample: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pointee_global_hash: Option<String>,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum CandidateScope {
    Finite,
    FiniteCollapsed,
    ModuleWide,
}

impl ModRefRecord {
    fn from_modref(mr: &ModRef, analysis: &Analysis) -> Self {
        let (candidate_scope, pointee_global_count, pointee_global_sample, pointee_global_hash) =
            match &mr.global {
                GlobalTarget::Name(_) => (None, None, Vec::new(), None),
                GlobalTarget::Unknown(_) => match analysis.affected_globals(mr) {
                    AffectedGlobals::ModuleWide => {
                        (Some(CandidateScope::ModuleWide), None, Vec::new(), None)
                    }
                    AffectedGlobals::Finite(globals) => {
                        let mut keys = globals
                            .iter()
                            .map(|&global| global_key(analysis, global))
                            .collect::<Vec<_>>();
                        keys.sort();
                        keys.dedup();
                        let mut exported = mr.pointee_globals.clone();
                        exported.sort();
                        exported.dedup();
                        if keys == exported {
                            (
                                Some(CandidateScope::Finite),
                                Some(keys.len()),
                                Vec::new(),
                                None,
                            )
                        } else {
                            let sample = keys.iter().take(8).cloned().collect();
                            let hash = Some(hash_global_keys(&keys));
                            (
                                Some(CandidateScope::FiniteCollapsed),
                                Some(keys.len()),
                                sample,
                                hash,
                            )
                        }
                    }
                },
            };
        Self {
            func: func_key(analysis, mr.func),
            global: match &mr.global {
                GlobalTarget::Name(id) => GlobalRecordTarget::Name {
                    name: global_key(analysis, *id),
                },
                GlobalTarget::Unknown(reason) => GlobalRecordTarget::Unknown {
                    unknown: reason.clone(),
                },
            },
            access: mr.access,
            via: mr.via,
            witness: mr.witness.clone(),
            detail: mr.detail.clone(),
            address_node: mr.address_node.clone(),
            pointee_globals: mr.pointee_globals.clone(),
            candidate_scope,
            pointee_global_count,
            pointee_global_sample,
            pointee_global_hash,
        }
    }
}

fn hash_global_keys(keys: &[String]) -> String {
    let mut hasher = Sha256::new();
    for key in keys {
        hasher.update((key.len() as u64).to_be_bytes());
        hasher.update(key.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

#[derive(Serialize)]
#[serde(untagged)]
enum GlobalRecordTarget {
    Name { name: String },
    Unknown { unknown: String },
}

#[derive(Serialize)]
struct StationarityRecord {
    global: String,
    complete_initval: bool,
    stationary: bool,
    reason: pangs_api::StationarityReason,
    runtime_writers: Vec<StationarityWriterRecord>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    initval_diagnostics: Vec<InitValDiagnosticRecord>,
}

impl StationarityRecord {
    fn from_verdict(verdict: &StationarityVerdict, analysis: &Analysis) -> Self {
        Self {
            global: global_key(analysis, verdict.global),
            complete_initval: verdict.complete_initval,
            stationary: verdict.stationary,
            reason: verdict.reason,
            runtime_writers: verdict
                .runtime_writers
                .iter()
                .map(|writer| StationarityWriterRecord::from_writer(writer, analysis))
                .collect(),
            initval_diagnostics: verdict
                .initval_diagnostics
                .iter()
                .map(InitValDiagnosticRecord::from_diagnostic)
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct InitValDiagnosticRecord {
    reason: String,
    witness: Option<String>,
}

impl InitValDiagnosticRecord {
    fn from_diagnostic(diagnostic: &pangs_api::InitValDiagnostic) -> Self {
        Self {
            reason: diagnostic.reason.clone(),
            witness: diagnostic.witness.clone(),
        }
    }
}

#[derive(Serialize)]
struct StationarityWriterRecord {
    func: Option<String>,
    global: GlobalRecordTarget,
    access: pangs_pir::Access,
    via: pangs_api::Via,
    witness: Option<String>,
}

impl StationarityWriterRecord {
    fn from_writer(writer: &StationarityWriter, analysis: &Analysis) -> Self {
        Self {
            func: writer.func.map(|id| func_key(analysis, id)),
            global: match &writer.global {
                GlobalTarget::Name(id) => GlobalRecordTarget::Name {
                    name: global_key(analysis, *id),
                },
                GlobalTarget::Unknown(reason) => GlobalRecordTarget::Unknown {
                    unknown: reason.clone(),
                },
            },
            access: writer.access,
            via: writer.via,
            witness: writer.witness.clone(),
        }
    }
}

#[derive(Serialize)]
struct ComponentsRecord {
    components: Vec<ComponentExport>,
    coverage: Coverage,
    context_rewrite: ContextRewriteExport,
}

impl ComponentsRecord {
    fn from_analysis(analysis: &Analysis) -> Self {
        Self {
            components: analysis
                .components()
                .iter()
                .map(|component| ComponentExport::from_component(component, analysis))
                .collect(),
            coverage: Coverage {
                mutable_globals_total: analysis.metrics().mutable_globals_total,
                in_rewritable_components: analysis.metrics().in_rewritable_components,
            },
            context_rewrite: ContextRewriteExport::from_analysis(analysis),
        }
    }
}

#[derive(Serialize)]
struct ContextRewriteExport {
    id: String,
    functions: Vec<String>,
    rewrite_callsites: Vec<String>,
    fields: Vec<ContextFieldExport>,
}

#[derive(Serialize)]
struct ContextFieldExport {
    global: String,
    accessors: Vec<String>,
    functions: Vec<String>,
    rewrite_callsites: Vec<String>,
    blockers: Vec<ContextRewriteBlockerExport>,
}

#[derive(Serialize)]
struct ContextRewriteBlockerExport {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    callsite: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    initializer: Option<String>,
}

impl ContextRewriteExport {
    fn from_analysis(analysis: &Analysis) -> Self {
        let plan = analysis.context_rewrite_plan();
        let function_name = |id| analysis.functions()[id].key.clone();
        let callsite_key = |id| analysis.callsites()[id].key.clone();
        Self {
            id: plan.id.clone(),
            functions: plan.functions.iter().copied().map(function_name).collect(),
            rewrite_callsites: plan
                .rewrite_callsites
                .iter()
                .copied()
                .map(callsite_key)
                .collect(),
            fields: plan
                .fields
                .iter()
                .map(|field| ContextFieldExport {
                    global: analysis.globals()[field.global].key.clone(),
                    accessors: field.accessors.iter().copied().map(function_name).collect(),
                    functions: field.functions.iter().copied().map(function_name).collect(),
                    rewrite_callsites: field
                        .rewrite_callsites
                        .iter()
                        .copied()
                        .map(callsite_key)
                        .collect(),
                    blockers: field
                        .blockers
                        .iter()
                        .map(|blocker| ContextRewriteBlockerExport {
                            kind: blocker.kind.clone(),
                            function: blocker.function.map(function_name),
                            callsite: blocker.callsite.map(callsite_key),
                            initializer: blocker.initializer.clone(),
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct ComponentExport {
    id: String,
    frozen: bool,
    taint: Vec<pangs_api::Taint>,
    members: Vec<String>,
    mutable_globals: Vec<String>,
}

impl ComponentExport {
    fn from_component(component: &ComponentInfo, analysis: &Analysis) -> Self {
        Self {
            id: component.id.clone(),
            frozen: component.frozen,
            taint: component.taint.clone(),
            members: component
                .members
                .iter()
                .map(|id| func_key(analysis, *id))
                .collect(),
            mutable_globals: component
                .mutable_globals
                .iter()
                .map(|id| global_key(analysis, *id))
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct Coverage {
    mutable_globals_total: usize,
    in_rewritable_components: usize,
}

fn func_key(analysis: &Analysis, id: FuncId) -> String {
    analysis.functions()[id].key.clone()
}

fn global_key(analysis: &Analysis, id: GlobalId) -> String {
    analysis.globals()[id].key.clone()
}

fn write_jsonl<T, I>(path: impl AsRef<Path>, records: I, files: &mut Vec<FileRecord>) -> Result<()>
where
    T: Serialize,
    I: IntoIterator<Item = T>,
{
    let path = path.as_ref();
    let file = File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut file = BufWriter::new(file);
    let mut count = 0;
    for record in records {
        serde_json::to_writer(&mut file, &record)?;
        file.write_all(b"\n")?;
        count += 1;
    }
    file.flush()?;
    files.push(FileRecord {
        name: path.file_name().unwrap().to_string_lossy().to_string(),
        records: count,
        sha256: sha256_file(path)?,
    });
    Ok(())
}

fn write_json<T: Serialize>(
    path: impl AsRef<Path>,
    value: &T,
    files: &mut Vec<FileRecord>,
) -> Result<()> {
    let path = path.as_ref();
    let file = File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut file = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.flush()?;
    if files.is_empty() && path.file_name().is_some_and(|name| name == "manifest.json") {
        return Ok(());
    }
    files.push(FileRecord {
        name: path.file_name().unwrap().to_string_lossy().to_string(),
        records: 1,
        sha256: sha256_file(path)?,
    });
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(data);
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;

    use std::time::Instant;

    use jsonschema::JSONSchema;
    use pangs_api::{Analysis, BuildMode, GlobalId, Opts, Stage};
    use pangs_manifest::{
        AuditRecord, Certificate, Extra, GlobalRecord as DispositionGlobal, Key,
        LocalizationVerdict, Manifest as DispositionManifest, Site,
    };
    use pangs_pir::Pir;
    use serde_json::json;
    use tempfile::TempDir;

    use super::{
        assemble_disposition_artifacts, atomic_access_recipe, check_traces,
        classify_violation_relevance, coupling_group_id, export_analysis, load_schema_for_artifact,
        localization_index, once_lock_pair_evidence, report, validate_export_dir,
        validate_value_against_schema, violation_relevance_witness, CertifiedGroupEvidence,
        ComponentsRecord, DispositionFactRows, ViolationRelevance,
    };

    fn group_site(line: u32) -> Site {
        Site {
            file: "group.c".into(),
            line,
            col: Some(1),
            function: Some("main".into()),
            extra: Extra::new(),
        }
    }

    fn signal_flag_artifacts(source: &str) -> (DispositionManifest, Vec<AuditRecord>) {
        const CLANG_14: &str = "/home/brk/tenjin/_local/xj-llvm-14/bin/clang";
        let temp = TempDir::new().unwrap();
        let source_path = temp.path().join("signal-flag.c");
        let bitcode_path = temp.path().join("signal-flag.bc");
        fs::write(&source_path, source).unwrap();
        assert!(Command::new(CLANG_14)
            .args(["-std=c11", "-O0", "-g", "-emit-llvm", "-c"])
            .arg(&source_path)
            .arg("-o")
            .arg(&bitcode_path)
            .status()
            .unwrap()
            .success());
        let pir = Pir::from_path(&bitcode_path).unwrap();
        let target = pir.target.clone().unwrap();
        let opts = Opts {
            build_mode: BuildMode::Executable,
            ..Opts::default()
        };
        let analysis = Analysis::run_with_disposition(&pir, &opts).unwrap();
        assemble_disposition_artifacts(
            &analysis,
            &pir,
            &opts,
            &bitcode_path,
            &workspace_root(),
            &target,
        )
        .unwrap()
    }

    fn manifest_global_by_llvm_name<'a>(
        manifest: &'a DispositionManifest,
        llvm_name: &str,
    ) -> &'a DispositionGlobal {
        manifest
            .globals
            .iter()
            .find(|global| global.meta.llvm_name == llvm_name)
            .unwrap()
    }

    fn add_disconnected_and_connected_audits(pir: &mut Pir) {
        let sig = pir
            .functions
            .iter()
            .find(|function| function.key == "main")
            .unwrap()
            .sig
            .clone();
        pir.functions.push(pangs_pir::Func {
            key: "cb".into(),
            sig,
            param_names: vec![],
            file: None,
            line: None,
            external: false,
            exported: false,
            address_taken: true,
            body: vec![],
        });
        let main = pir
            .functions
            .iter_mut()
            .find(|function| function.key == "main")
            .unwrap();
        main.body.extend([
            pangs_pir::Stmt::Assign {
                dest: "%fp".into(),
                sources: vec!["cb".into()],
                loc: None,
            },
            pangs_pir::Stmt::PtrToInt {
                dest: "%fp_bits".into(),
                source: "%fp".into(),
                integer_bits: None,
                pointer_bits: None,
                pointer_address_space: None,
                comparison_only: false,
                loc: None,
            },
            pangs_pir::Stmt::Assign {
                dest: "%mixed".into(),
                sources: vec!["cb".into(), "@G00".into()],
                loc: None,
            },
            pangs_pir::Stmt::PtrToInt {
                dest: "%mixed_bits".into(),
                source: "%mixed".into(),
                integer_bits: None,
                pointer_bits: None,
                pointer_address_space: None,
                comparison_only: false,
                loc: None,
            },
            pangs_pir::Stmt::Alloca {
                dest: "%callbacks".into(),
                ty: "{ void ()*, i32 }".into(),
                loc: None,
            },
            pangs_pir::Stmt::Memcpy {
                dst: "%callbacks".into(),
                src: "%callbacks".into(),
                bytes: Some(16),
                proven_fnptr_init: false,
                loc: None,
            },
        ]);
    }

    #[test]
    fn once_lock_pair_evidence_requires_overlap_path_and_shared_init() {
        let evidence = |earliest, latest, path: u64, init: &[&str]| CertifiedGroupEvidence {
            publication_function: "main".into(),
            descent_path: json!([path]),
            earliest: group_site(earliest),
            latest: group_site(latest),
            init_functions: init.iter().map(|name| (*name).into()).collect(),
        };
        let left = evidence(10, 20, 1, &["initialize", "left"]);
        let right = evidence(15, 25, 1, &["initialize", "right"]);
        let pair = once_lock_pair_evidence(&left, &right).unwrap();
        assert_eq!(pair.extra["common_interval"]["earliest"]["line"], 15);
        assert_eq!(pair.extra["common_interval"]["latest"]["line"], 20);
        assert_eq!(pair.extra["shared_init_functions"], json!(["initialize"]));

        assert!(once_lock_pair_evidence(&left, &evidence(21, 25, 1, &["initialize"])).is_none());
        assert!(once_lock_pair_evidence(&left, &evidence(15, 18, 2, &["initialize"])).is_none());
        assert!(once_lock_pair_evidence(&left, &evidence(15, 18, 1, &["other"])).is_none());
    }

    #[test]
    fn coupling_group_id_is_independent_of_member_order() {
        let left = Key::new("group.c", "left").unwrap();
        let right = Key::new("group.c", "right").unwrap();
        assert_eq!(
            coupling_group_id(&[left.clone(), right.clone()]),
            coupling_group_id(&[right.clone(), left.clone()])
        );
    }

    #[test]
    fn disposition_keys_a_mutable_definition_without_source_metadata() {
        let fixture = workspace_root().join("fixtures/synthetic/trivial/module.pir.json");
        let mut pir = Pir::from_path(&fixture).unwrap();
        pir.globals[0].file = None;
        pir.globals[0].line = None;
        pir.globals[0].type_spelling = Some("int".into());
        pir.globals[0].size_bits = Some(32);
        pir.globals[0].align_bits = Some(32);
        pir.globals[0].scalar_class = Some(pangs_pir::ScalarTypeClass::Integer);
        pir.globals[0].signed = Some(true);
        pir.globals[0].initializer_ir = Some("i32 0".into());
        let loc = Some(pangs_pir::Loc {
            file: "fixtures/synthetic/trivial/trivial.c".into(),
            line: 4,
            col: 3,
            dir: None,
            filename: None,
        });
        pir.functions[0].body.splice(
            0..1,
            [
                pangs_pir::Stmt::Load {
                    dest: "%old".into(),
                    address: "@g_counter".into(),
                    volatile: false,
                    access_bytes: Some(4),
                    loc: loc.clone(),
                },
                pangs_pir::Stmt::GlobalRef {
                    global: "g_counter".into(),
                    access: pangs_pir::Access::Ref,
                    volatile: false,
                    loc: loc.clone(),
                },
                pangs_pir::Stmt::ScalarOp {
                    dest: "%new".into(),
                    op: pangs_pir::ScalarOp::Add,
                    lhs: "%old".into(),
                    rhs: "1".into(),
                    loc: loc.clone(),
                },
                pangs_pir::Stmt::Store {
                    address: "@g_counter".into(),
                    value: "%new".into(),
                    volatile: false,
                    access_bytes: Some(4),
                    loc: loc.clone(),
                },
                pangs_pir::Stmt::GlobalRef {
                    global: "g_counter".into(),
                    access: pangs_pir::Access::Mod,
                    volatile: false,
                    loc,
                },
            ],
        );
        let opts = Opts::default();
        let analysis = Analysis::run_with_disposition(&pir, &opts).unwrap();
        let target = pangs_pir::TargetInfo {
            triple: "x86_64-unknown-linux-gnu".into(),
            data_layout: String::new(),
            supported_atomic_widths: vec![8, 16, 32, 64],
        };
        let (manifest, ledger) = assemble_disposition_artifacts(
            &analysis,
            &pir,
            &opts,
            &fixture,
            &workspace_root(),
            &target,
        )
        .unwrap();

        assert_eq!(manifest.globals.len(), 1);
        assert_eq!(manifest.globals[0].key.to_string(), "g_counter");
        assert_eq!(manifest.globals[0].meta.file, None);
        assert!(manifest.unkeyed_globals.is_empty());
        assert!(ledger[0].text.contains("globally unique"));
        let Some(Certificate::Certified { certificate, .. }) =
            &manifest.globals[0].facts.atomic_eligibility
        else {
            panic!("direct source-mapped scalar accesses should certify atomic eligibility")
        };
        assert_eq!(
            certificate["recipe"]["accesses"][0]["operation"],
            "fetch_add"
        );
        assert_eq!(certificate["recipe"]["accesses"][0]["operand"], "1");
        assert!(certificate["recipe"]["declaration"]["file"].is_null());
        assert_eq!(
            certificate["recipe"]["declaration"]["initializer_ir"],
            "i32 0"
        );
        assert_eq!(certificate["recipe"]["declaration"]["align_bits"], 32);
        assert_eq!(
            certificate["recipe"]["declaration"]["scalar_class"],
            "integer"
        );
        assert_eq!(certificate["recipe"]["declaration"]["signed"], true);
        assert_eq!(certificate["source_materialization"]["status"], "blocked");
        assert_eq!(
            certificate["source_materialization"]["code"],
            "declaration-source-unmapped"
        );
    }

    #[test]
    fn unnamed_compound_literal_rolls_into_unique_initializer_owner() {
        let fixture = workspace_root().join("fixtures/synthetic/trivial/module.pir.json");
        let mut pir = Pir::from_path(&fixture).unwrap();
        pir.globals[0].init_refs.push(".compoundliteral".into());
        pir.globals.push(pangs_pir::Global {
            key: ".compoundliteral".into(),
            linkage: pangs_pir::SymbolLinkage::Internal,
            size_bits: Some(128),
            align_bits: Some(64),
            ..pangs_pir::Global::default()
        });
        // Retain the owner's original runtime write and add a read-only runtime reference to its
        // backing storage. The latter is init-value stable, but must still receive a localization
        // candidate so storage-closure folding cannot erase the owner's localization fact.
        pir.functions[0].body.insert(
            0,
            pangs_pir::Stmt::GlobalRef {
                global: ".compoundliteral".into(),
                access: pangs_pir::Access::Ref,
                volatile: false,
                loc: None,
            },
        );
        pir.functions[0].body.insert(
            1,
            pangs_pir::Stmt::Store {
                address: "@g_counter".into(),
                value: "0".into(),
                volatile: false,
                access_bytes: Some(4),
                loc: None,
            },
        );
        let opts = Opts {
            stage: Stage::Andersen,
            ..Opts::default()
        };
        let analysis = Analysis::run_with_disposition(&pir, &opts).unwrap();
        let backing = analysis
            .globals()
            .iter()
            .find(|global| global.key == ".compoundliteral")
            .unwrap();
        assert_eq!(
            backing.synthetic_kind.as_deref(),
            Some("unnamed-compound-literal")
        );
        assert!(backing.initval_stable);
        let target = pangs_pir::TargetInfo {
            triple: "x86_64-unknown-linux-gnu".into(),
            data_layout: String::new(),
            supported_atomic_widths: vec![8, 16, 32, 64],
        };
        let (manifest, _) = assemble_disposition_artifacts(
            &analysis,
            &pir,
            &opts,
            &fixture,
            &workspace_root(),
            &target,
        )
        .unwrap();

        assert_eq!(manifest.globals.len(), 1);
        assert_eq!(
            manifest.globals[0].key.to_string(),
            "fixtures/synthetic/trivial/trivial.c::g_counter"
        );
        assert_eq!(manifest.globals[0].storage_members.len(), 1);
        assert!(manifest.globals[0].facts.written.value);
        assert!(manifest.globals[0].facts.localization.is_some());
        assert_eq!(
            manifest.globals[0].storage_members[0].llvm_name,
            ".compoundliteral"
        );
        assert_eq!(manifest.synthetic_globals.len(), 1);
        assert_eq!(
            manifest.synthetic_globals[0]
                .owner
                .as_ref()
                .map(ToString::to_string),
            Some("fixtures/synthetic/trivial/trivial.c::g_counter".into())
        );
        manifest.validate().unwrap();
    }

    #[test]
    fn shared_compound_literal_remains_ownerless_diagnostic_storage() {
        let fixture = workspace_root().join("fixtures/synthetic/trivial/module.pir.json");
        let mut pir = Pir::from_path(&fixture).unwrap();
        pir.globals[0].init_refs.push(".compoundliteral".into());
        pir.globals.push(pangs_pir::Global {
            key: "second_owner".into(),
            file: Some("fixtures/synthetic/trivial/trivial.c".into()),
            line: Some(2),
            linkage: pangs_pir::SymbolLinkage::Internal,
            init_refs: vec![".compoundliteral".into()],
            ..pangs_pir::Global::default()
        });
        pir.globals.push(pangs_pir::Global {
            key: ".compoundliteral".into(),
            linkage: pangs_pir::SymbolLinkage::Internal,
            size_bits: Some(128),
            align_bits: Some(64),
            ..pangs_pir::Global::default()
        });
        let opts = Opts::default();
        let analysis = Analysis::run_with_disposition(&pir, &opts).unwrap();
        let target = pangs_pir::TargetInfo {
            triple: "x86_64-unknown-linux-gnu".into(),
            data_layout: String::new(),
            supported_atomic_widths: vec![8, 16, 32, 64],
        };
        let (manifest, _) = assemble_disposition_artifacts(
            &analysis,
            &pir,
            &opts,
            &fixture,
            &workspace_root(),
            &target,
        )
        .unwrap();

        assert_eq!(manifest.globals.len(), 2);
        assert!(manifest
            .globals
            .iter()
            .all(|global| global.storage_members.is_empty()));
        assert_eq!(manifest.synthetic_globals.len(), 1);
        assert!(manifest.synthetic_globals[0].owner.is_none());
        assert!(manifest.synthetic_globals[0]
            .witness
            .note
            .as_deref()
            .unwrap()
            .contains("no unique"));
        manifest.validate().unwrap();
    }

    #[test]
    fn localization_reports_static_initializer_address_dependency() {
        let fixture = workspace_root().join("fixtures/synthetic/trivial/module.pir.json");
        let mut pir = Pir::from_path(&fixture).unwrap();
        pir.globals.push(pangs_pir::Global {
            key: "address_table".into(),
            file: Some("fixtures/synthetic/trivial/trivial.c".into()),
            line: Some(2),
            is_const: true,
            mutable: false,
            init_refs: vec!["g_counter".into()],
            ..pangs_pir::Global::default()
        });
        let opts = Opts {
            build_mode: BuildMode::Executable,
            ..Opts::default()
        };
        let analysis = Analysis::run_with_disposition(&pir, &opts).unwrap();
        let global = analysis.lookup_global("g_counter").unwrap();

        let localization = localization_index(&analysis)[global.0 as usize]
            .as_ref()
            .unwrap()
            .clone();

        assert_eq!(localization.verdict, LocalizationVerdict::Blocked);
        assert_eq!(localization.blockers.len(), 1);
        assert_eq!(
            localization.blockers[0].code,
            "aggregate-initializer-address-dependency"
        );
        assert_eq!(
            localization.blockers[0].witness.symbol.as_deref(),
            Some("address_table")
        );
        assert_eq!(
            localization.blockers[0].witness.note.as_deref(),
            Some("static initializer for address_table retains the address of g_counter")
        );

        let components = serde_json::to_value(ComponentsRecord::from_analysis(&analysis)).unwrap();
        let blocker = &components["context_rewrite"]["fields"][0]["blockers"][0];
        assert_eq!(blocker["initializer"], "address_table");
        assert!(blocker.get("function").is_none());
        let schema_json = Box::leak(Box::new(
            load_schema_for_artifact("components.json").unwrap(),
        ));
        let schema = JSONSchema::compile(schema_json).unwrap();
        validate_value_against_schema(&schema, &components, "initializer blocker").unwrap();
    }

    #[test]
    fn initval_stable_global_still_has_a_localization_fact() {
        let fixture = workspace_root().join("fixtures/synthetic/trivial/module.pir.json");
        let mut pir = Pir::from_path(&fixture).unwrap();
        let pangs_pir::Stmt::GlobalRef { access, .. } = &mut pir.functions[0].body[0] else {
            panic!("trivial fixture starts with a global access")
        };
        *access = pangs_pir::Access::Ref;
        let analysis = Analysis::run_with_disposition(
            &pir,
            &Opts {
                stage: Stage::Andersen,
                build_mode: BuildMode::Executable,
                ..Opts::default()
            },
        )
        .unwrap();
        let global = analysis.lookup_global("g_counter").unwrap();

        assert!(analysis.globals()[global].initval_stable);
        assert!(localization_index(&analysis)[global.0 as usize].is_some());
    }

    #[test]
    fn volatile_global_access_blocks_atomic_eligibility() {
        let fixture = workspace_root().join("fixtures/synthetic/trivial/module.pir.json");
        let mut pir = Pir::from_path(&fixture).unwrap();
        pir.globals[0].type_spelling = Some("int".into());
        pir.globals[0].size_bits = Some(32);
        pir.globals[0].align_bits = Some(32);
        pir.globals[0].scalar_class = Some(pangs_pir::ScalarTypeClass::Integer);
        pir.globals[0].signed = Some(true);
        pir.globals[0].initializer_ir = Some("i32 0".into());
        pir.functions[0].body.insert(
            0,
            pangs_pir::Stmt::GlobalRef {
                global: "g_counter".into(),
                access: pangs_pir::Access::Ref,
                volatile: true,
                loc: Some(pangs_pir::Loc {
                    file: "fixtures/synthetic/trivial/trivial.c".into(),
                    line: 4,
                    col: 3,
                    dir: None,
                    filename: None,
                }),
            },
        );
        let opts = Opts::default();
        let analysis = Analysis::run_with_disposition(&pir, &opts).unwrap();
        let target = pangs_pir::TargetInfo {
            triple: "x86_64-unknown-linux-gnu".into(),
            data_layout: String::new(),
            supported_atomic_widths: vec![8, 16, 32, 64],
        };
        let (manifest, _) = assemble_disposition_artifacts(
            &analysis,
            &pir,
            &opts,
            &fixture,
            &workspace_root(),
            &target,
        )
        .unwrap();

        let Some(Certificate::Failed {
            codes, witnesses, ..
        }) = &manifest.globals[0].facts.atomic_eligibility
        else {
            panic!("volatile access must fail atomic eligibility")
        };
        assert!(codes.iter().any(|code| code == "volatile-access"));
        assert!(witnesses
            .iter()
            .any(|witness| witness.kind == "atomic-volatile-access"));
    }

    #[test]
    fn source_atomic_qualifier_blocks_atomic_eligibility() {
        let fixture = workspace_root().join("fixtures/synthetic/trivial/module.pir.json");
        let mut pir = Pir::from_path(&fixture).unwrap();
        pir.globals[0].type_spelling = Some("atomic_int".into());
        pir.globals[0].scalar_type_evidence = Some(pangs_pir::ScalarTypeEvidence {
            type_spelling: Some("atomic_int".into()),
            typedef_chain: vec!["atomic_int".into()],
            qualifiers: pangs_pir::TypeQualifiers {
                is_atomic: true,
                ..pangs_pir::TypeQualifiers::default()
            },
            class: Some(pangs_pir::ScalarTypeClass::Integer),
            signed: Some(true),
        });
        pir.globals[0].size_bits = Some(32);
        pir.globals[0].align_bits = Some(32);
        pir.globals[0].scalar_class = Some(pangs_pir::ScalarTypeClass::Integer);
        pir.globals[0].signed = Some(true);
        pir.globals[0].initializer_ir = Some("i32 0".into());
        let opts = Opts::default();
        let analysis = Analysis::run_with_disposition(&pir, &opts).unwrap();
        let target = pangs_pir::TargetInfo {
            triple: "x86_64-unknown-linux-gnu".into(),
            data_layout: String::new(),
            supported_atomic_widths: vec![8, 16, 32, 64],
        };
        let (manifest, _) = assemble_disposition_artifacts(
            &analysis,
            &pir,
            &opts,
            &fixture,
            &workspace_root(),
            &target,
        )
        .unwrap();

        let Some(Certificate::Failed {
            codes,
            witnesses,
            recipe,
            ..
        }) = &manifest.globals[0].facts.atomic_eligibility
        else {
            panic!("a source _Atomic global must fail atomic eligibility")
        };
        assert!(manifest.globals[0].facts.word_sized_scalar.value);
        assert_eq!(codes, &["source-atomic-unsupported"]);
        assert_eq!(witnesses[0].kind, "source-atomic-unsupported");
        assert!(recipe.is_none());
    }

    #[test]
    fn signal_flag_v1_certifies_one_closed_internal_candidate() {
        let (manifest, ledger) = signal_flag_artifacts(
            r#"
#include <signal.h>
static volatile sig_atomic_t flag;
int poll_flag(void) { return flag; }
void set_flag(void) { flag = 1; }
"#,
        );
        let flag = manifest_global_by_llvm_name(&manifest, "flag");
        let Some(Certificate::Certified { certificate, .. }) = &flag.facts.atomic_eligibility
        else {
            panic!("closed internal volatile sig_atomic_t should certify")
        };
        assert_eq!(certificate["recipe"]["mode"], "signal-flag-v1");
        assert_eq!(certificate["recipe"]["ordering"], "seq_cst");
        assert_eq!(
            certificate["recipe"]["accesses"].as_array().unwrap().len(),
            2
        );
        assert!(certificate.get("signal_lock_free").is_none());
        assert!(ledger
            .iter()
            .any(|record| record.kind == "signal-flag-assumptions"));
        manifest.validate().unwrap();

        let schema_value: serde_json::Value = serde_json::from_slice(
            &fs::read(workspace_root().join("schemas/disposition-manifest.schema.json")).unwrap(),
        )
        .unwrap();
        let schema_value = Box::leak(Box::new(schema_value));
        let schema = JSONSchema::compile(schema_value).unwrap();
        let manifest_value = serde_json::to_value(&manifest).unwrap();
        assert!(schema.validate(&manifest_value).is_ok());

        let mut bad_ordering = manifest.clone();
        let Certificate::Certified { certificate, .. } = bad_ordering.globals[0]
            .facts
            .atomic_eligibility
            .as_mut()
            .unwrap()
        else {
            unreachable!()
        };
        certificate["recipe"]["ordering"] = json!("relaxed");
        assert!(bad_ordering.validate().is_err());
        assert!(schema
            .validate(&serde_json::to_value(&bad_ordering).unwrap())
            .is_err());
    }

    #[test]
    fn signal_flag_v1_rejects_two_candidates_and_function_local_nonclosure() {
        let (two, _) = signal_flag_artifacts(
            r#"
#include <signal.h>
static volatile sig_atomic_t first;
static volatile sig_atomic_t second;
int poll_flags(void) { return first || second; }
"#,
        );
        for name in ["first", "second"] {
            let global = manifest_global_by_llvm_name(&two, name);
            let Some(Certificate::Failed {
                codes,
                witnesses,
                recipe,
                ..
            }) = &global.facts.atomic_eligibility
            else {
                panic!("multiple provisional candidates must fail")
            };
            assert_eq!(codes, &["signal-flag-access-functions-not-closed"]);
            assert_eq!(witnesses[0].extra["candidate_count"], 2);
            assert!(recipe.is_none());
        }

        let (not_closed, _) = signal_flag_artifacts(
            r#"
#include <signal.h>
static volatile sig_atomic_t flag;
static volatile int other;
int poll_flag(void) { return flag + other; }
"#,
        );
        let flag = manifest_global_by_llvm_name(&not_closed, "flag");
        let Some(Certificate::Failed {
            codes,
            witnesses,
            recipe,
            ..
        }) = &flag.facts.atomic_eligibility
        else {
            panic!("an unrelated volatile in an access function must fail")
        };
        assert_eq!(codes, &["signal-flag-access-functions-not-closed"]);
        assert_eq!(witnesses[0].extra["function"], "poll_flag");
        assert_eq!(witnesses[0].extra["operation"], "load");
        assert!(witnesses[0].extra["statement_index"].is_u64());
        assert!(recipe.is_none());
    }

    #[test]
    fn signal_flag_v1_ignores_unrelated_volatile_in_other_function() {
        let (manifest, _) = signal_flag_artifacts(
            r#"
#include <signal.h>
static volatile sig_atomic_t flag;
static volatile int other;
int poll_other(void) { return other; }
int poll_flag(void) { int value = flag; return value + poll_other(); }
"#,
        );
        let flag = manifest_global_by_llvm_name(&manifest, "flag");
        assert!(matches!(
            flag.facts.atomic_eligibility,
            Some(Certificate::Certified { .. })
        ));
    }

    #[test]
    fn signal_flag_v1_rejects_storage_linkage_machine_and_access_exclusions() {
        let cases = [
            (
                "external",
                "#include <signal.h>\nvolatile sig_atomic_t flag; int read_flag(void) { return flag; }\n",
            ),
            (
                "thread-local",
                "#include <signal.h>\nstatic _Thread_local volatile sig_atomic_t flag; int read_flag(void) { return flag; }\n",
            ),
            (
                "section",
                "#include <signal.h>\nstatic volatile sig_atomic_t flag __attribute__((section(\".flags\"))); int read_flag(void) { return flag; }\n",
            ),
            (
                "unsigned",
                "typedef unsigned int sig_atomic_t; static volatile sig_atomic_t flag; int read_flag(void) { return flag; }\n",
            ),
            (
                "wide",
                "typedef long sig_atomic_t; static volatile sig_atomic_t flag; long read_flag(void) { return flag; }\n",
            ),
            (
                "over-aligned",
                "typedef int sig_atomic_t; static volatile sig_atomic_t flag __attribute__((aligned(8))); int read_flag(void) { return flag; }\n",
            ),
            (
                "rmw",
                "#include <signal.h>\nstatic volatile sig_atomic_t flag; void increment_flag(void) { flag++; }\n",
            ),
            (
                "address-escape",
                "#include <signal.h>\nstatic volatile sig_atomic_t flag; static volatile sig_atomic_t *pointer = &flag; int read_flag(void) { return *pointer; }\n",
            ),
        ];
        for (label, source) in cases {
            let (manifest, ledger) = signal_flag_artifacts(source);
            let flag = manifest_global_by_llvm_name(&manifest, "flag");
            assert!(
                !matches!(
                    flag.facts.atomic_eligibility,
                    Some(Certificate::Certified { .. })
                ),
                "{label} unexpectedly certified"
            );
            if let Some(Certificate::Failed { recipe, .. }) = &flag.facts.atomic_eligibility {
                assert!(recipe.is_none(), "{label} retained a partial recipe");
            }
            assert!(
                ledger
                    .iter()
                    .all(|record| record.kind != "signal-flag-assumptions"),
                "{label} emitted assumptions without certification"
            );
        }
    }

    #[test]
    fn pointer_derived_access_site_retains_statement_volatility() {
        const CLANG_14: &str = "/home/brk/tenjin/_local/xj-llvm-14/bin/clang";
        let temp = TempDir::new().unwrap();
        let source_path = temp.path().join("volatile-pointer.c");
        let bitcode_path = temp.path().join("volatile-pointer.bc");
        fs::write(
            &source_path,
            r#"
static volatile int target;
static int read_pointer(volatile int *pointer) { return *pointer; }
int call_reader(void) { return read_pointer(&target); }
"#,
        )
        .unwrap();
        assert!(Command::new(CLANG_14)
            .args(["-std=c11", "-O0", "-g", "-emit-llvm", "-c"])
            .arg(&source_path)
            .arg("-o")
            .arg(&bitcode_path)
            .status()
            .unwrap()
            .success());
        let pir = Pir::from_path(&bitcode_path).unwrap();
        let analysis = Analysis::run_with_disposition(
            &pir,
            &Opts {
                stage: Stage::Andersen,
                ..Opts::default()
            },
        )
        .unwrap();
        let target = analysis.lookup_global("target").unwrap();
        let read_pointer = analysis.lookup_func("read_pointer").unwrap();
        let site = analysis
            .access_sites()
            .iter()
            .find(|site| site.func == read_pointer && site.affects(target))
            .expect("pointer load should resolve to the internal global");
        assert_ne!(site.via, pangs_api::Via::Direct);
        assert!(site.volatile);
    }

    #[test]
    fn mutex_eligibility_rejects_call_paths_between_accessors() {
        let fixture = workspace_root().join("fixtures/synthetic/trivial/module.pir.json");
        let mut pir = Pir::from_path(&fixture).unwrap();
        let main = pir
            .functions
            .iter_mut()
            .find(|function| function.key == "main")
            .unwrap();
        main.body
            .retain(|statement| matches!(statement, pangs_pir::Stmt::CallDirect { .. }));
        main.body.insert(
            0,
            pangs_pir::Stmt::GlobalRef {
                global: "g_counter".into(),
                access: pangs_pir::Access::Ref,
                volatile: false,
                loc: None,
            },
        );
        let driver = pir
            .functions
            .iter_mut()
            .find(|function| function.key == "driver")
            .unwrap();
        driver.body = vec![pangs_pir::Stmt::GlobalRef {
            global: "g_counter".into(),
            access: pangs_pir::Access::Mod,
            volatile: false,
            loc: None,
        }];
        let target = pir
            .functions
            .iter_mut()
            .find(|function| function.key == "target")
            .unwrap();
        target.body = vec![pangs_pir::Stmt::GlobalRef {
            global: "isolated".into(),
            access: pangs_pir::Access::Mod,
            volatile: false,
            loc: None,
        }];
        pir.globals.push(pangs_pir::Global {
            key: "isolated".into(),
            mutable: true,
            ..pangs_pir::Global::default()
        });

        let opts = Opts::default();
        let analysis = Analysis::run_with_disposition(&pir, &opts).unwrap();
        let target = pangs_pir::TargetInfo {
            triple: "x86_64-unknown-linux-gnu".into(),
            data_layout: String::new(),
            supported_atomic_widths: vec![8, 16, 32, 64],
        };
        let (manifest, _) = assemble_disposition_artifacts(
            &analysis,
            &pir,
            &opts,
            &fixture,
            &workspace_root(),
            &target,
        )
        .unwrap();

        let reentrant = manifest
            .globals
            .iter()
            .find(|global| global.meta.llvm_name == "g_counter")
            .unwrap();
        let Some(Certificate::Failed {
            codes, witnesses, ..
        }) = &reentrant.facts.mutex_eligibility
        else {
            panic!("an accessor-to-accessor call path must fail mutex eligibility")
        };
        assert!(codes.iter().any(|code| code == "reentrant-access-path"));
        let path = witnesses
            .iter()
            .find(|witness| witness.kind == "mutex-reentrant-access-path")
            .unwrap();
        assert_eq!(path.extra["call_path"][0]["caller"], "main");
        assert_eq!(path.extra["call_path"][0]["callee"], "driver");

        let isolated = manifest
            .globals
            .iter()
            .find(|global| global.meta.llvm_name == "isolated")
            .unwrap();
        let Some(Certificate::Certified { certificate, .. }) = &isolated.facts.mutex_eligibility
        else {
            panic!("an isolated accessor should certify mutex eligibility")
        };
        assert_eq!(certificate["reentrancy"]["model"], "final-call-graph-v1");
        assert_eq!(
            certificate["lock_recipe"]["scope"],
            "whole-accessor-function-v1"
        );
        assert_eq!(certificate["accessor_functions"], json!(["target"]));
    }

    #[test]
    fn mutex_eligibility_rejects_unknown_callees_reachable_from_an_accessor() {
        let fixture = workspace_root().join("fixtures/synthetic/trivial/module.pir.json");
        let mut pir = Pir::from_path(&fixture).unwrap();
        let unknown_call = pir
            .functions
            .iter()
            .find(|function| function.key == "main")
            .and_then(|function| {
                function.body.iter().find_map(|statement| match statement {
                    pangs_pir::Stmt::CallDirect { .. } => Some(statement.clone()),
                    _ => None,
                })
            })
            .unwrap();
        let unknown_call = match unknown_call {
            pangs_pir::Stmt::CallDirect {
                sig,
                args,
                dest,
                loc,
                ..
            } => pangs_pir::Stmt::CallDirect {
                callee: "missing_external".into(),
                sig,
                args,
                dest,
                loc,
            },
            _ => unreachable!(),
        };
        let target = pir
            .functions
            .iter_mut()
            .find(|function| function.key == "target")
            .unwrap();
        target.body = vec![
            pangs_pir::Stmt::GlobalRef {
                global: "isolated".into(),
                access: pangs_pir::Access::Mod,
                volatile: false,
                loc: None,
            },
            unknown_call,
        ];
        pir.globals.push(pangs_pir::Global {
            key: "isolated".into(),
            mutable: true,
            ..pangs_pir::Global::default()
        });

        let opts = Opts::default();
        let analysis = Analysis::run_with_disposition(&pir, &opts).unwrap();
        let target_info = pangs_pir::TargetInfo {
            triple: "x86_64-unknown-linux-gnu".into(),
            data_layout: String::new(),
            supported_atomic_widths: vec![8, 16, 32, 64],
        };
        let (manifest, _) = assemble_disposition_artifacts(
            &analysis,
            &pir,
            &opts,
            &fixture,
            &workspace_root(),
            &target_info,
        )
        .unwrap();

        let isolated = manifest
            .globals
            .iter()
            .find(|global| global.meta.llvm_name == "isolated")
            .unwrap();
        let Some(Certificate::Failed {
            codes, witnesses, ..
        }) = &isolated.facts.mutex_eligibility
        else {
            panic!("an unresolved callee reachable from an accessor must fail closed")
        };
        assert!(codes.iter().any(|code| code == "unknown-callee-reentrancy"));
        let witness = witnesses
            .iter()
            .find(|witness| witness.kind == "mutex-unknown-callee-reentrancy")
            .unwrap();
        assert_eq!(witness.extra["call_path"][0]["caller"], "target");
        assert_eq!(
            witness.extra["call_path"][0]["callee"]["unknown"],
            "external_callee"
        );
    }

    #[test]
    fn mutex_certificate_carries_declaration_and_blocks_an_empty_accessor_recipe() {
        let fixture = workspace_root().join("fixtures/synthetic/trivial/module.pir.json");
        let mut pir = Pir::from_path(&fixture).unwrap();
        pir.globals.push(pangs_pir::Global {
            key: "table".into(),
            file: Some("fixtures/synthetic/trivial/trivial.c".into()),
            line: Some(20),
            type_spelling: Some("struct entry[4]".into()),
            size_bits: Some(256),
            align_bits: Some(64),
            initializer_ir: Some("[4 x %struct.entry] zeroinitializer".into()),
            mutable: true,
            ..pangs_pir::Global::default()
        });
        pir.global_init.push(pangs_pir::Stmt::GlobalRef {
            global: "table".into(),
            access: pangs_pir::Access::Mod,
            volatile: false,
            loc: None,
        });

        let opts = Opts::default();
        let analysis = Analysis::run_with_disposition(&pir, &opts).unwrap();
        let target = pangs_pir::TargetInfo {
            triple: "x86_64-unknown-linux-gnu".into(),
            data_layout: String::new(),
            supported_atomic_widths: vec![8, 16, 32, 64],
        };
        let (manifest, _) = assemble_disposition_artifacts(
            &analysis,
            &pir,
            &opts,
            &fixture,
            &workspace_root(),
            &target,
        )
        .unwrap();

        let table = manifest
            .globals
            .iter()
            .find(|global| global.meta.llvm_name == "table")
            .unwrap();
        assert!(
            !table.facts.written.value,
            "a static initializer is not a runtime write"
        );
        let Some(Certificate::Certified { certificate, .. }) = &table.facts.mutex_eligibility
        else {
            panic!("a complete empty runtime access set is statically mutex-eligible")
        };
        assert_eq!(certificate["declaration"]["llvm_name"], "table");
        assert_eq!(certificate["declaration"]["size_bits"], 256);
        assert_eq!(certificate["declaration"]["align_bits"], 64);
        assert_eq!(
            certificate["declaration"]["initializer_ir"],
            "[4 x %struct.entry] zeroinitializer"
        );
        assert_eq!(
            certificate["source_materialization"]["code"],
            "no-runtime-accessor-sites"
        );
    }

    #[test]
    fn nearby_load_store_without_scalar_dataflow_is_not_an_rmw() {
        let fixture = workspace_root().join("fixtures/synthetic/trivial/module.pir.json");
        let mut pir = Pir::from_path(&fixture).unwrap();
        pir.globals[0].type_spelling = Some("int".into());
        pir.globals[0].size_bits = Some(32);
        pir.globals[0].align_bits = Some(32);
        pir.globals[0].scalar_class = Some(pangs_pir::ScalarTypeClass::Integer);
        pir.globals[0].signed = Some(true);
        pir.globals[0].initializer_ir = Some("i32 0".into());
        pir.functions[0].body.insert(
            0,
            pangs_pir::Stmt::GlobalRef {
                global: "g_counter".into(),
                access: pangs_pir::Access::Ref,
                volatile: false,
                loc: Some(pangs_pir::Loc {
                    file: "fixtures/synthetic/trivial/trivial.c".into(),
                    line: 4,
                    col: 3,
                    dir: None,
                    filename: None,
                }),
            },
        );
        let opts = Opts::default();
        let analysis = Analysis::run_with_disposition(&pir, &opts).unwrap();
        let target = pangs_pir::TargetInfo {
            triple: "x86_64-unknown-linux-gnu".into(),
            data_layout: String::new(),
            supported_atomic_widths: vec![8, 16, 32, 64],
        };
        let (manifest, _) = assemble_disposition_artifacts(
            &analysis,
            &pir,
            &opts,
            &fixture,
            &workspace_root(),
            &target,
        )
        .unwrap();

        let Some(Certificate::Failed { codes, .. }) = &manifest.globals[0].facts.atomic_eligibility
        else {
            panic!("proximity alone must not certify an RMW")
        };
        assert!(codes.iter().any(|code| code == "rmw-shape-unclassified"));
    }

    #[test]
    fn scalar_phi_current_global_proof_recovers_the_source_rmw_recipe() {
        let fixture = workspace_root().join("fixtures/synthetic/disposition/scalar_phi_rmw.ll");
        let pir = Pir::from_path(&fixture).unwrap();
        let opts = Opts::default();
        let analysis = Analysis::run_with_disposition(&pir, &opts).unwrap();
        let global = analysis.lookup_global("g").unwrap();
        let sites = analysis.access_sites_for_global(global).collect::<Vec<_>>();

        let (recipe, failures) = atomic_access_recipe(&analysis, &sites, None, "g");
        assert!(failures.is_empty(), "{failures:#?}");
        let recipe = recipe.unwrap();
        assert_eq!(recipe.len(), 2);
        assert!(recipe.iter().all(|entry| entry["operation"] == "fetch_add"));
        assert!(recipe.iter().all(|entry| entry["operand"] == "1"));
        assert!(recipe.iter().any(|entry| entry["site"]["line"] == 10));
    }

    #[test]
    fn collapsed_finite_modref_does_not_poison_an_outside_global() {
        let fixture = workspace_root().join("fixtures/synthetic/m1_6/high_fanout_modref.pir.json");
        let pir = Pir::from_path(&fixture).unwrap();
        let opts = Opts {
            stage: pangs_api::Stage::Steens,
            build_mode: pangs_api::BuildMode::Executable,
            ..Opts::default()
        };
        let analysis = Analysis::run_with_disposition(&pir, &opts).unwrap();
        let collapsed = analysis
            .modrefs()
            .iter()
            .find(|row| {
                matches!(&row.global, pangs_api::GlobalTarget::Unknown(reason) if reason == "omega_store")
                    && row
                        .detail
                        .as_deref()
                        .is_some_and(|detail| detail.starts_with("high_fanout_pointer_modref:"))
            })
            .unwrap();
        let pangs_api::AffectedGlobals::Finite(candidates) = analysis.affected_globals(collapsed)
        else {
            panic!("collapsed finite row widened to module-wide")
        };
        let untouched = analysis.lookup_global("@Untouched").unwrap();
        assert_eq!(candidates.len(), 17);
        assert!(!candidates.contains(&untouched));

        let target = pangs_pir::TargetInfo {
            triple: "x86_64-unknown-linux-gnu".into(),
            data_layout: String::new(),
            supported_atomic_widths: vec![8, 16, 32, 64],
        };
        let (manifest, _) = assemble_disposition_artifacts(
            &analysis,
            &pir,
            &opts,
            &fixture,
            &workspace_root(),
            &target,
        )
        .unwrap();
        let untouched = manifest
            .globals
            .iter()
            .find(|global| global.meta.llvm_name == "@Untouched")
            .unwrap();
        assert!(untouched.facts.access_set_complete.value);
        let touched = manifest
            .globals
            .iter()
            .find(|global| global.meta.llvm_name == "@G00")
            .unwrap();
        assert!(touched.facts.access_set_complete.value);
        let Some(Certificate::Failed {
            codes, diagnostics, ..
        }) = &touched.facts.atomic_eligibility
        else {
            panic!("coarse atomic gates must produce a failed D3 certificate")
        };
        assert!(codes.iter().any(|code| code == "word-sized-scalar"));
        let diagnostics = diagnostics.as_ref().unwrap();
        assert_eq!(
            diagnostics["access_lowering"]["status"], "skipped",
            "a decisive coarse gate must bound access-lowering diagnostics"
        );
        assert_eq!(
            manifest.run.analysis.extra["phase_stationarity_report"]["bounded_indirect_accesses"]
                ["globals"],
            17
        );
    }

    #[test]
    fn finite_audit_flow_only_taints_connected_high_fanout_candidate() {
        let fixture = workspace_root().join("fixtures/synthetic/m1_6/high_fanout_modref.pir.json");
        let mut pir = Pir::from_path(&fixture).unwrap();
        add_disconnected_and_connected_audits(&mut pir);
        let opts = Opts {
            stage: pangs_api::Stage::Andersen,
            build_mode: pangs_api::BuildMode::Executable,
            ..Opts::default()
        };
        let analysis = Analysis::run_with_disposition(&pir, &opts).unwrap();
        let facts = DispositionFactRows::new(&analysis);
        let g00 = analysis.lookup_global("@G00").unwrap();
        let g01 = analysis.lookup_global("@G01").unwrap();

        assert_eq!(
            facts.violation[g00.0 as usize].as_ref().unwrap().kind,
            "violation-address-relevant"
        );
        assert!(facts.violation[g01.0 as usize].is_none());
        assert!(facts.violation_diagnostics[g01.0 as usize]
            .iter()
            .filter(|diagnostic| diagnostic.finding_kind == "fnptr_ptrtoint")
            .all(|diagnostic| diagnostic.classification == ViolationRelevance::Unrelated.into()));
        assert!(facts.violation_diagnostics[g01.0 as usize]
            .iter()
            .filter(|diagnostic| diagnostic.finding_kind == "memcpy_fnptr_aggregate")
            .all(|diagnostic| diagnostic.classification == ViolationRelevance::Unrelated.into()));
    }

    #[test]
    fn unrelated_varargs_finding_does_not_taint_direct_scalar_access() {
        let fixture = workspace_root().join("fixtures/synthetic/m1_5/audit_surface.pir.json");
        let mut pir = Pir::from_path(&fixture).unwrap();
        pir.functions
            .iter_mut()
            .find(|function| function.key == "driver")
            .unwrap()
            .body
            .retain(|statement| {
                matches!(statement, pangs_pir::Stmt::CallDirect { callee, .. } if callee == "accept_vararg")
            });
        pir.functions
            .iter_mut()
            .find(|function| function.key == "driver")
            .unwrap()
            .body
            .insert(
                0,
                pangs_pir::Stmt::GlobalRef {
                    global: "@AuditedGlobal".into(),
                    access: pangs_pir::Access::Ref,
                    volatile: false,
                    loc: None,
                },
            );
        pir.globals.push(pangs_pir::Global {
            key: "@AuditedGlobal".into(),
            ..pangs_pir::Global::default()
        });
        let opts = Opts {
            build_mode: pangs_api::BuildMode::Executable,
            ..Opts::default()
        };
        let analysis = Analysis::run_with_disposition(&pir, &opts).unwrap();
        let target = pangs_pir::TargetInfo {
            triple: "x86_64-unknown-linux-gnu".into(),
            data_layout: String::new(),
            supported_atomic_widths: vec![8, 16, 32, 64],
        };
        let (manifest, _) = assemble_disposition_artifacts(
            &analysis,
            &pir,
            &opts,
            &fixture,
            &workspace_root(),
            &target,
        )
        .unwrap();
        let global = manifest
            .globals
            .iter()
            .find(|global| global.meta.llvm_name == "@AuditedGlobal")
            .unwrap();
        assert!(!global.facts.violation_taint.value);
        assert!(global.facts.access_set_complete.value);
        assert_eq!(
            global.facts.violation_relevance[0].classification,
            pangs_manifest::ViolationRelevance::Unrelated
        );
        assert_eq!(
            global.facts.violation_relevance[0].finding_kind,
            "fnptr_varargs_external"
        );
    }

    #[test]
    fn finding_that_names_global_object_remains_hard_relevant() {
        let fixture = workspace_root().join("fixtures/synthetic/m1_5/audit_surface.pir.json");
        let mut pir = Pir::from_path(&fixture).unwrap();
        let driver = pir
            .functions
            .iter_mut()
            .find(|function| function.key == "driver")
            .unwrap();
        driver.body.retain(
            |statement| matches!(statement, pangs_pir::Stmt::Unknown { reason, .. } if reason.starts_with("inline_asm")),
        );
        let pangs_pir::Stmt::Unknown { operands, .. } = &mut driver.body[0] else {
            unreachable!()
        };
        operands.push("@AuditedGlobal".into());
        driver.body.insert(
            0,
            pangs_pir::Stmt::GlobalRef {
                global: "@AuditedGlobal".into(),
                access: pangs_pir::Access::Ref,
                volatile: false,
                loc: None,
            },
        );
        pir.globals.push(pangs_pir::Global {
            key: "@AuditedGlobal".into(),
            ..pangs_pir::Global::default()
        });
        let opts = Opts {
            build_mode: pangs_api::BuildMode::Executable,
            ..Opts::default()
        };
        let analysis = Analysis::run_with_disposition(&pir, &opts).unwrap();
        let facts = DispositionFactRows::new(&analysis);
        let global = analysis.lookup_global("@AuditedGlobal").unwrap();
        let witness = facts.violation[global.0 as usize].as_ref().unwrap();
        assert_eq!(witness.kind, "violation-address-relevant");
        assert_eq!(
            facts.violation_diagnostics[global.0 as usize][0].classification,
            ViolationRelevance::AddressRelevant.into()
        );
    }

    #[test]
    fn unknown_finding_kind_defaults_to_unresolved() {
        let fixture = workspace_root().join("fixtures/synthetic/trivial/module.pir.json");
        let pir = Pir::from_path(&fixture).unwrap();
        let analysis = Analysis::run_with_disposition(&pir, &Opts::default()).unwrap();
        let global = GlobalId(0);
        let function = analysis.modrefs()[0].func;
        let rows = analysis
            .modrefs()
            .iter()
            .filter(|row| row.func == function)
            .collect::<Vec<_>>();
        let finding = pangs_api::Finding {
            kind: "future_unknown_violation".into(),
            file: None,
            line: None,
            affected: vec!["value:%opaque".into()],
            effect: "omega_taint".into(),
            detail: None,
            function: Some(function),
            global_flow: pangs_api::AuditGlobalFlow::NotComputed,
        };
        assert_eq!(
            classify_violation_relevance(&analysis, &finding, function, global, &rows),
            ViolationRelevance::Unresolved
        );
        assert_eq!(
            violation_relevance_witness(
                &analysis,
                &finding,
                function,
                global,
                ViolationRelevance::Unresolved,
            )
            .kind,
            "violation-relevance-unresolved"
        );
    }

    #[test]
    fn check_traces_flags_a_target_outside_the_edge_set() {
        let dir = TempDir::new().unwrap();
        // One indirect callsite resolved to {target}; no unknown edge → not permissive.
        fs::write(
            dir.path().join("callgraph.jsonl"),
            "{\"caller\":{\"func\":\"main\"},\"callsite\":\"main@!noloc#0\",\"callee\":{\"func\":\"target\"},\"kind\":\"indirect\",\"tier\":\"andersen\"}\n",
        )
        .unwrap();
        let trace = dir.path().join("trace.txt");

        // Observed target in the set → clean.
        fs::write(&trace, "main\t0\ttarget\n").unwrap();
        assert!(check_traces(dir.path(), &trace).unwrap().is_clean());

        // Observed target NOT in the set → violation (the soundness catch).
        fs::write(&trace, "main\t0\trogue\n").unwrap();
        let report = check_traces(dir.path(), &trace).unwrap();
        assert!(!report.is_clean());
        assert!(report.violations[0].contains("rogue"));
    }

    #[test]
    fn check_traces_permits_targets_at_unknown_sites() {
        let dir = TempDir::new().unwrap();
        // Site carries an unknown (Ω) callee edge → permissive: any observed target is ok.
        fs::write(
            dir.path().join("callgraph.jsonl"),
            "{\"caller\":{\"func\":\"main\"},\"callsite\":\"main@!noloc#0\",\"callee\":{\"unknown\":\"omega_fnptr\"},\"kind\":\"indirect\",\"tier\":\"andersen\"}\n",
        )
        .unwrap();
        let trace = dir.path().join("trace.txt");
        fs::write(&trace, "main\t0\tanything\n").unwrap();
        assert!(check_traces(dir.path(), &trace).unwrap().is_clean());
    }

    #[test]
    fn validate_export_dir_rejects_schema_mismatch() {
        let fixture = workspace_root().join("fixtures/synthetic/trivial/module.pir.json");
        let pir = Pir::from_path(&fixture).unwrap();
        let analysis = Analysis::run(&pir, &Opts::default()).unwrap();
        let outdir = TempDir::new().unwrap();

        export_analysis(
            &analysis,
            &Opts::default(),
            &fixture,
            outdir.path(),
            false,
            Instant::now(),
        )
        .unwrap();
        fs::write(
            outdir.path().join("metrics.json"),
            "{\"functions\":\"bad\",\"globals\":0,\"callsites\":0,\"call_edges\":0,\"audit_findings\":0,\"mutable_globals_total\":0,\"in_rewritable_components\":0,\"partition_count\":0,\"partition_p50_size\":0,\"partition_p95_size\":0,\"partition_max_size\":0,\"oversize_fallbacks\":0,\"oversize_fallback_max_size\":0,\"rounds\":0,\"analysis_wall_us\":0,\"setup_scan_us\":0,\"preanalysis_us\":0,\"pag_build_us\":0,\"solve_us\":0,\"solver_postprocess_us\":0,\"pointer_modref_us\":0,\"callgraph_dedup_us\":0,\"modref_dedup_us\":0,\"stationarity_us\":0,\"initval_reapply_us\":0,\"transitive_modref_us\":0,\"findings_dedup_us\":0,\"components_us\":0,\"metrics_bookkeeping_us\":0}\n",
        )
        .unwrap();

        let err = validate_export_dir(outdir.path()).unwrap_err().to_string();
        assert!(err.contains("metrics.json"));
        assert!(err.contains("schema validation failed"));
    }

    #[test]
    fn report_includes_pipeline_and_phase_timings() {
        let fixture = workspace_root().join("fixtures/synthetic/trivial/module.pir.json");
        let pir = Pir::from_path(&fixture).unwrap();
        let analysis = Analysis::run(&pir, &Opts::default()).unwrap();
        let outdir = TempDir::new().unwrap();

        export_analysis(
            &analysis,
            &Opts::default(),
            &fixture,
            outdir.path(),
            false,
            Instant::now(),
        )
        .unwrap();

        let text = report(outdir.path()).unwrap();
        assert!(text.contains("pipeline wall: "));
        assert!(text.contains("analysis wall: "));
        assert!(text.contains("setup scan: "));
        assert!(text.contains("preanalysis: "));
        assert!(text.contains("pag build: "));
        assert!(text.contains("solve: "));
        assert!(text.contains("solver postprocess: "));
        assert!(text.contains("pointer modref: "));
        assert!(text.contains("callgraph dedup: "));
        assert!(text.contains("modref dedup: "));
        assert!(text.contains("stationarity: "));
        assert!(text.contains("initval reapply: "));
        assert!(text.contains("transitive modref: "));
        assert!(text.contains("findings dedup: "));
        assert!(text.contains("components: "));
        assert!(text.contains("metrics bookkeeping: "));
        assert!(text.contains("icalls by tier: "));
        assert!(text.contains("call edges by tier: "));
        assert!(text.contains("confined functions: "));
        assert!(text.contains("initval complete globals: "));
        assert!(text.contains("initval-stable globals: "));
        assert!(text.contains("stationarity reasons: "));
        assert!(text.contains("oversize fallbacks: "));
        assert!(text.contains("audit kinds: "));
        assert!(text.contains("audit effects: "));
        assert!(text.contains("component sizes: "));
        assert!(text.contains("largest frozen components: "));
        assert!(text.contains("component taints: "));
        assert!(text.contains("component blockers: "));
    }

    fn workspace_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }
}

/// Result of validating a dynamic icall trace against an export directory.
#[derive(Debug, Default)]
pub struct TraceReport {
    /// (caller, idx, target) pairs that are not in the analysis's edge set.
    pub violations: Vec<String>,
    pub checked: usize,
    /// Trace rows whose target could not be resolved to a symbol (dladdr "?").
    pub unresolved: usize,
}

impl TraceReport {
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }
}

/// M1.8 dynamic icall validation: assert every observed `(caller, idx, target)` in a trace
/// file is permitted by the analysis's indirect-call edge set in `dir/callgraph.jsonl`.
///
/// `idx` is the static index of an indirect call among its function's indirect calls (in
/// instruction order). The analysis's indirect callsites for a caller, ordered by their
/// key ordinal, are in the same order — so trace `idx` selects the matching callsite. A
/// callsite that already carries an unknown (Ω) callee edge is permissive (the analysis
/// conceded it cannot bound that site, so no observed target there is a violation).
pub fn check_traces(dir: &Path, trace: &Path) -> Result<TraceReport> {
    let callgraph = dir.join("callgraph.jsonl");
    let file = File::open(&callgraph).with_context(|| format!("open {}", callgraph.display()))?;

    // caller -> callsite_key -> (allowed targets, permissive?)
    use std::collections::{BTreeMap, BTreeSet};
    let mut sites: BTreeMap<String, BTreeMap<String, (BTreeSet<String>, bool)>> = BTreeMap::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let row: Value = serde_json::from_str(&line)?;
        if row.get("kind").and_then(Value::as_str) != Some("indirect") {
            continue;
        }
        let Some(caller) = row["caller"].get("func").and_then(Value::as_str) else {
            continue;
        };
        let Some(callsite) = row.get("callsite").and_then(Value::as_str) else {
            continue;
        };
        let entry = sites
            .entry(caller.to_string())
            .or_default()
            .entry(callsite.to_string())
            .or_insert_with(|| (BTreeSet::new(), false));
        match row["callee"].get("func").and_then(Value::as_str) {
            Some(func) => {
                entry.0.insert(func.to_string());
            }
            None => {
                // unknown/Ω callee → permissive site
                entry.1 = true;
            }
        }
    }

    // For each caller, order its indirect callsite keys by their ordinal (the trailing
    // `#<n>` segment), giving the same index the runtime counts.
    let ordered: BTreeMap<String, Vec<String>> = sites
        .iter()
        .map(|(caller, by_key)| {
            let mut keys: Vec<String> = by_key.keys().cloned().collect();
            keys.sort_by_key(|k| key_ordinal(k));
            (caller.clone(), keys)
        })
        .collect();

    let trace_file = File::open(trace).with_context(|| format!("open {}", trace.display()))?;
    let mut report = TraceReport::default();
    for line in BufReader::new(trace_file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let mut cols = line.split('\t');
        let caller = cols.next().unwrap_or("").to_string();
        let idx: usize = cols.next().unwrap_or("").parse().unwrap_or(usize::MAX);
        let target = cols.next().unwrap_or("").to_string();
        report.checked += 1;
        if target == "?" {
            report.unresolved += 1;
            continue;
        }
        let Some(keys) = ordered.get(&caller) else {
            report.violations.push(format!(
                "{caller}#{idx}: caller has no indirect callsites in the analysis, observed target {target}"
            ));
            continue;
        };
        let Some(key) = keys.get(idx) else {
            report.violations.push(format!(
                "{caller}#{idx}: observed indirect call index out of range (analysis has {} sites), target {target}",
                keys.len()
            ));
            continue;
        };
        let (allowed, permissive) = &sites[&caller][key];
        if *permissive || allowed.contains(&target) {
            continue;
        }
        report.violations.push(format!(
            "{key}: observed target {target} not in analysis edge set {{{}}}",
            allowed.iter().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    Ok(report)
}

/// Parse the trailing `#<n>` ordinal of a callsite key; keys without one sort last.
fn key_ordinal(key: &str) -> u64 {
    key.rsplit_once('#')
        .and_then(|(_, n)| n.parse().ok())
        .unwrap_or(u64::MAX)
}
