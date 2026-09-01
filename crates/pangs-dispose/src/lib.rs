use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use pangs_manifest::{
    canonicalize_audit, to_canonical_json, AuditRecord, AuditScope, AuditSource, CascadeSkip,
    Certificate, DisposeMode, DisposeRun, Disposition, DispositionProvenance, Extra, Facts,
    GroupProvenance, GuardFailure, Key, LocalizationVerdict, Manifest, OnceLockGroupSupport,
    OverrideCounts, OverrideEcho, OverrideOutcome, OverrideReport, OverrideReportEntry,
    OverrideRequested, OverrideScope, SharedGuardFailures, SkipReason, Strategy, Witness,
};
use serde::Deserialize;
use tempfile::NamedTempFile;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("cascade order contains duplicate strategy {0}")]
    Duplicate(String),
    #[error("unhandled is implicit and may not appear in the cascade order")]
    ExplicitUnhandled,
    #[error("localize may not appear in a library-mode cascade")]
    LocalizeInLibrary,
}

#[derive(Debug, Error)]
pub enum DisposeError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Manifest(#[from] pangs_manifest::Error),
    #[error("disposition ledger is missing: {0}")]
    MissingLedger(PathBuf),
    #[error("invalid overrides: {0}")]
    InvalidOverrides(String),
    #[error("one or more overrides were rejected or unmatched (artifacts were written)")]
    OverrideProblems,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Overrides {
    pub globals: BTreeMap<String, OverrideSpec>,
    pub groups: BTreeMap<String, OverrideSpec>,
    pub cascade: Option<CascadeOverride>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverrideSpec {
    pub disposition: Strategy,
    #[serde(default)]
    pub accept_risk: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CascadeOverride {
    pub order: Vec<Strategy>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyOutcome {
    pub override_problems: bool,
}

pub fn parse_overrides(text: &str) -> Result<Overrides, DisposeError> {
    toml::from_str(text).map_err(|error| DisposeError::InvalidOverrides(error.to_string()))
}

pub fn config_with_overrides(
    mode: DisposeMode,
    overrides: Option<&Overrides>,
) -> Result<CascadeConfig, DisposeError> {
    let mut config = CascadeConfig::default_for(mode);
    if let Some(order) = overrides.and_then(|value| value.cascade.as_ref()) {
        config.order = order.order.clone();
    }
    config.validate()?;
    Ok(config)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CascadeConfig {
    pub mode: DisposeMode,
    pub order: Vec<Strategy>,
}

impl CascadeConfig {
    pub fn default_for(mode: DisposeMode) -> Self {
        let order = match mode {
            DisposeMode::Application => Strategy::DEFAULT_APPLICATION.to_vec(),
            DisposeMode::Library => Strategy::DEFAULT_LIBRARY.to_vec(),
        };
        Self { mode, order }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut seen = BTreeSet::new();
        for strategy in &self.order {
            if *strategy == Strategy::Unhandled {
                return Err(ConfigError::ExplicitUnhandled);
            }
            if !seen.insert(*strategy) {
                return Err(ConfigError::Duplicate(strategy.as_str().to_owned()));
            }
            if self.mode == DisposeMode::Library && *strategy == Strategy::Localize {
                return Err(ConfigError::LocalizeInLibrary);
            }
        }
        Ok(())
    }
}

pub fn cascade(
    facts: &Facts,
    config: &CascadeConfig,
) -> Result<(Strategy, Vec<CascadeSkip>), ConfigError> {
    config.validate()?;
    let mut trace = Vec::new();
    for strategy in &config.order {
        match evaluate(*strategy, facts) {
            GuardResult::Applicable => return Ok((*strategy, trace)),
            GuardResult::Failed(failed) => trace.push(CascadeSkip {
                strategy: *strategy,
                reason: SkipReason::GuardFailed {
                    failed,
                    extra: Extra::new(),
                },
                extra: Extra::new(),
            }),
            GuardResult::NotComputed(fact) => trace.push(CascadeSkip {
                strategy: *strategy,
                reason: SkipReason::FactNotComputed {
                    fact: fact.to_owned(),
                    extra: Extra::new(),
                },
                extra: Extra::new(),
            }),
        }
    }
    Ok((Strategy::Unhandled, trace))
}

/// Apply only the independent cascade. D2 layers overrides and group resolution over this
/// output without changing `cascade_chosen` or `cascade_trace`.
pub fn apply_independent_cascade(
    manifest: &mut Manifest,
    config: &CascadeConfig,
    overrides_file: Option<String>,
    overrides_sha256: Option<String>,
) -> Result<(), DisposeError> {
    config.validate()?;
    if manifest.materialization.take().is_some() {
        eprintln!("warning: dropping stale disposition materialization section");
    }
    for global in &mut manifest.globals {
        let (chosen, cascade_trace) = cascade(&global.facts, config)?;
        global.disposition = Some(Disposition {
            chosen,
            cascade_chosen: chosen,
            provenance: DispositionProvenance::Cascade,
            cascade_trace,
            r#override: None,
            demotion: None,
            extra: Extra::new(),
        });
    }
    manifest.run.dispose = Some(DisposeRun {
        mode: config.mode,
        cascade: config.order.clone(),
        overrides_file,
        overrides_sha256,
        extra: Extra::new(),
    });
    manifest.override_report = Some(OverrideReport {
        entries: Vec::new(),
        counts: OverrideCounts::default(),
        extra: Extra::new(),
    });
    manifest.canonicalize();
    Ok(())
}

pub fn apply_policy(
    manifest: &mut Manifest,
    ledger: &mut Vec<AuditRecord>,
    config: &CascadeConfig,
    overrides: Option<&Overrides>,
    overrides_file: Option<String>,
    overrides_sha256: Option<String>,
) -> Result<PolicyOutcome, DisposeError> {
    apply_independent_cascade(manifest, config, overrides_file, overrides_sha256)?;
    ledger.retain(|record| record.source != AuditSource::Override);
    let mut entries = Vec::new();

    if let Some(overrides) = overrides {
        resolve_groups(manifest, overrides, config, &mut entries, ledger)?;
        for (raw_key, spec) in &overrides.globals {
            let key = Key::parse(raw_key)?;
            let Some(index) = manifest.globals.iter().position(|global| global.key == key) else {
                entries.push(report_entry(
                    OverrideScope::Global,
                    Some(raw_key.clone()),
                    spec,
                    OverrideOutcome::UnmatchedKey,
                    Some("no manifest global has this key".into()),
                    None,
                ));
                continue;
            };
            let group_disposition = global_group_disposition(manifest, &key);
            apply_global_override(
                &mut manifest.globals[index],
                spec,
                config,
                group_disposition,
                &mut entries,
                ledger,
            )?;
        }
        if let Some(cascade_override) = &overrides.cascade {
            entries.push(OverrideReportEntry {
                scope: OverrideScope::Cascade,
                key: None,
                requested: OverrideRequested::Order(cascade_override.order.clone()),
                accept_risk: false,
                outcome: OverrideOutcome::Honored,
                reason: None,
                witness: None,
                failures: None,
                extra: Extra::new(),
            });
        }
    } else {
        resolve_groups(
            manifest,
            &Overrides::default(),
            config,
            &mut entries,
            ledger,
        )?;
    }

    entries.sort_by(|a, b| {
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
    let counts = count_outcomes(&entries);
    let override_problems = counts.rejected > 0
        || counts.rejected_strategy_disabled > 0
        || counts.rejected_strategy_unavailable > 0
        || counts.rejected_no_recipe > 0
        || counts.unmatched_key > 0;
    manifest.override_report = Some(OverrideReport {
        entries,
        counts,
        extra: Extra::new(),
    });
    emit_measurement_report(manifest);
    canonicalize_audit(ledger)?;
    manifest.canonicalize();
    Ok(PolicyOutcome { override_problems })
}

/// Emit the inexpensive M3 gate measurements from facts and finalized policy output. These are
/// deliberately an observation of existing facts, not a partial implementation of D3 or D4.
fn emit_measurement_report(manifest: &mut Manifest) {
    let strategies = [
        Strategy::Immutable,
        Strategy::OnceLock,
        Strategy::Atomic,
        Strategy::Mutex,
        Strategy::Localize,
        Strategy::Unhandled,
    ];
    let mut distribution = BTreeMap::new();
    for strategy in &strategies {
        distribution.insert(strategy.as_str().to_owned(), 0_u64);
    }

    let mut skip_histogram = BTreeMap::<String, serde_json::Value>::new();
    let mut skip_counts = strategies
        .iter()
        .map(|strategy| {
            (
                strategy.as_str().to_owned(),
                (0_u64, BTreeMap::new(), BTreeMap::new()),
            )
        })
        .collect::<BTreeMap<String, (u64, BTreeMap<String, u64>, BTreeMap<String, u64>)>>();
    let mut atomic_candidates = 0_u64;
    let mut atomic_word_sized = 0_u64;
    let mut atomic_access_complete = 0_u64;
    let mut atomic_free_gate_eligible = 0_u64;
    let mut atomic_certified = 0_u64;
    let mut mutex_candidates = 0_u64;
    let mut mutex_access_complete = 0_u64;
    let mut mutex_signal_safe = 0_u64;
    let mut localized_globals = 0_u64;
    let mut localized_known_size_bits = 0_u64;
    let mut localized_unknown_size = 0_u64;
    let mut localized_components = BTreeMap::<String, (u64, u64, u64)>::new();

    for global in &manifest.globals {
        let disposition = global
            .disposition
            .as_ref()
            .expect("measurement report requires finalized dispositions");
        *distribution
            .get_mut(disposition.chosen.as_str())
            .expect("all strategies have a distribution bucket") += 1;

        for skip in &disposition.cascade_trace {
            let entry = skip_counts
                .entry(skip.strategy.as_str().to_owned())
                .or_default();
            entry.0 += 1;
            match &skip.reason {
                SkipReason::GuardFailed { failed, .. } => {
                    for guard in failed {
                        *entry.1.entry(guard.clone()).or_default() += 1;
                    }
                }
                SkipReason::FactNotComputed { fact, .. } => {
                    *entry.2.entry(fact.clone()).or_default() += 1;
                }
            }
        }

        let gate_candidate = matches!(
            disposition.chosen,
            Strategy::Atomic | Strategy::Localize | Strategy::Unhandled
        );
        if gate_candidate {
            atomic_candidates += 1;
            if global.facts.word_sized_scalar.value {
                atomic_word_sized += 1;
                if global.facts.access_set_complete.value {
                    atomic_access_complete += 1;
                    atomic_free_gate_eligible += 1;
                }
            }
            if global
                .facts
                .atomic_eligibility
                .as_ref()
                .is_some_and(Certificate::is_certified)
            {
                atomic_certified += 1;
            }

            mutex_candidates += 1;
            if global.facts.access_set_complete.value {
                mutex_access_complete += 1;
                if !global.facts.signal_context_access.value {
                    mutex_signal_safe += 1;
                }
            }
        }

        if disposition.chosen == Strategy::Localize {
            localized_globals += 1;
            let component = global
                .facts
                .localization
                .as_ref()
                .map(|localization| localization.component.clone())
                .unwrap_or_else(|| "<missing>".into());
            let component_counts = localized_components.entry(component).or_default();
            component_counts.0 += 1;
            if let Some(size_bits) = global.meta.size_bits {
                localized_known_size_bits += size_bits;
                component_counts.1 += size_bits;
            } else {
                localized_unknown_size += 1;
                component_counts.2 += 1;
            }
        }
    }

    for (strategy, (total, guard_failed, fact_not_computed)) in skip_counts {
        skip_histogram.insert(
            strategy,
            serde_json::json!({
                "total": total,
                "guard_failed": guard_failed,
                "fact_not_computed": fact_not_computed,
            }),
        );
    }
    let components = localized_components
        .into_iter()
        .map(
            |(component, (globals, known_size_bits, unknown_size_globals))| {
                (
                    component,
                    serde_json::json!({
                        "globals": globals,
                        "known_size_bits": known_size_bits,
                        "unknown_size_globals": unknown_size_globals,
                    }),
                )
            },
        )
        .collect::<BTreeMap<_, _>>();
    let override_usage = manifest
        .override_report
        .as_ref()
        .map(|report| {
            serde_json::json!({
                "honored": report.counts.honored,
                "accepted_risk": report.counts.honored_accepted_risk,
                "rejected": report.counts.rejected
                    + report.counts.rejected_strategy_disabled
                    + report.counts.rejected_strategy_unavailable
                    + report.counts.rejected_no_recipe,
                "unmatched_key": report.counts.unmatched_key,
            })
        })
        .unwrap_or_else(|| serde_json::json!({}));
    let report = serde_json::json!({
        "disposition_distribution": distribution,
        "cascade_skip_histogram": skip_histogram,
        "would_be_eligibility": {
            "atomic": {
                "candidate_disposition": atomic_candidates,
                "word_sized_scalar": atomic_word_sized,
                "access_set_complete": atomic_access_complete,
                "free_gate_eligible": atomic_free_gate_eligible,
                "certificate_eligible": atomic_certified,
                "eligible": atomic_certified,
            },
            "mutex": {
                "candidate_disposition": mutex_candidates,
                "access_set_complete": mutex_access_complete,
                "signal_context_safe": mutex_signal_safe,
                "eligible": mutex_signal_safe,
            },
        },
        "context_struct_pressure": {
            "localized_globals": localized_globals,
            "known_size_bits": localized_known_size_bits,
            "unknown_size_globals": localized_unknown_size,
            "components": components,
        },
        "override_usage": override_usage,
    });
    manifest
        .run
        .dispose
        .as_mut()
        .expect("policy application creates dispose run metadata")
        .extra
        .insert("measurement_report".into(), report);
}

fn apply_global_override(
    global: &mut pangs_manifest::GlobalRecord,
    spec: &OverrideSpec,
    config: &CascadeConfig,
    group_disposition: Option<Strategy>,
    entries: &mut Vec<OverrideReportEntry>,
    ledger: &mut Vec<AuditRecord>,
) -> Result<(), DisposeError> {
    let key = global.key.to_string();
    let disposition = global
        .disposition
        .as_mut()
        .expect("independent cascade populated disposition");
    if group_disposition.is_some_and(|group| group != spec.disposition) {
        entries.push(report_entry(
            OverrideScope::Global,
            Some(key),
            spec,
            OverrideOutcome::Rejected,
            Some("member pin conflicts with the resolved coupling-group disposition".into()),
            None,
        ));
        return Ok(());
    }
    if spec.disposition != Strategy::Unhandled && !config.order.contains(&spec.disposition) {
        entries.push(report_entry(
            OverrideScope::Global,
            Some(key),
            spec,
            OverrideOutcome::RejectedStrategyDisabled,
            Some("strategy is omitted from the configured cascade".into()),
            None,
        ));
        return Ok(());
    }
    if spec.disposition == Strategy::Unhandled {
        honor_override(disposition, spec, false);
        entries.push(report_entry(
            OverrideScope::Global,
            Some(key),
            spec,
            OverrideOutcome::Honored,
            None,
            None,
        ));
        return Ok(());
    }

    if let Some(outcome) = unavailable_outcome(spec.disposition, &global.facts) {
        entries.push(report_entry(
            OverrideScope::Global,
            Some(key),
            spec,
            outcome,
            Some(match outcome {
                OverrideOutcome::RejectedNoRecipe => {
                    "eligibility failed and supplied no materialization recipe".into()
                }
                _ => "strategy inputs were not computed".into(),
            }),
            None,
        ));
        return Ok(());
    }

    match evaluate(spec.disposition, &global.facts) {
        GuardResult::Applicable => {
            honor_override(disposition, spec, false);
            entries.push(report_entry(
                OverrideScope::Global,
                Some(key),
                spec,
                OverrideOutcome::Honored,
                None,
                None,
            ));
        }
        GuardResult::NotComputed(_) => {
            entries.push(report_entry(
                OverrideScope::Global,
                Some(key),
                spec,
                OverrideOutcome::RejectedStrategyUnavailable,
                Some("strategy inputs were not computed".into()),
                None,
            ));
        }
        GuardResult::Failed(guards) => {
            let failures =
                SharedGuardFailures::from(guard_failures(&global.key, &global.facts, &guards));
            if spec.accept_risk {
                honor_override(disposition, spec, true);
                entries.push(report_entry(
                    OverrideScope::Global,
                    Some(key.clone()),
                    spec,
                    OverrideOutcome::HonoredAcceptedRisk,
                    None,
                    Some(failures.clone()),
                ));
                ledger.push(AuditRecord {
                    id: String::new(),
                    kind: "accepted-risk".into(),
                    scope: AuditScope::Global {
                        key: global.key.clone(),
                        extra: Extra::new(),
                    },
                    source: AuditSource::Override,
                    text: spec.reason.clone().unwrap_or_else(|| {
                        format!("accepted risk for {} on {key}", spec.disposition.as_str())
                    }),
                    witness: None,
                    failures: Some(failures),
                    extra: Extra::new(),
                });
            } else {
                entries.push(report_entry(
                    OverrideScope::Global,
                    Some(key),
                    spec,
                    OverrideOutcome::Rejected,
                    Some("strategy guard failed and accept_risk was not set".into()),
                    Some(failures),
                ));
            }
        }
    }
    Ok(())
}

fn global_group_disposition(manifest: &Manifest, key: &Key) -> Option<Strategy> {
    manifest
        .coupling_groups
        .iter()
        .find(|group| group.members.contains(key))
        .and_then(|group| group.group_disposition)
}

fn resolve_groups(
    manifest: &mut Manifest,
    overrides: &Overrides,
    config: &CascadeConfig,
    entries: &mut Vec<OverrideReportEntry>,
    ledger: &mut Vec<AuditRecord>,
) -> Result<(), DisposeError> {
    let mut matched = BTreeSet::new();
    for group_index in 0..manifest.coupling_groups.len() {
        let group_id = manifest.coupling_groups[group_index].id.clone();
        let member_keys = manifest.coupling_groups[group_index].members.clone();
        manifest.coupling_groups[group_index].group_provenance = Some(GroupProvenance::Cascade);
        manifest.coupling_groups[group_index].r#override = None;
        let override_spec = overrides.groups.get(&group_id);
        if override_spec.is_some() {
            matched.insert(group_id.clone());
        }

        let chosen = if let Some(spec) = override_spec {
            if matches!(
                spec.disposition,
                Strategy::Immutable | Strategy::Atomic | Strategy::Localize
            ) {
                entries.push(report_entry(
                    OverrideScope::Group,
                    Some(group_id.clone()),
                    spec,
                    OverrideOutcome::Rejected,
                    Some(
                        "per-global strategy cannot be pinned at group scope; use member overrides"
                            .into(),
                    ),
                    None,
                ));
                independent_joint_group_strategy(manifest, group_index, config)
            } else if spec.disposition != Strategy::Unhandled
                && !config.order.contains(&spec.disposition)
            {
                entries.push(report_entry(
                    OverrideScope::Group,
                    Some(group_id.clone()),
                    spec,
                    OverrideOutcome::RejectedStrategyDisabled,
                    Some("strategy is omitted from the configured cascade".into()),
                    None,
                ));
                independent_joint_group_strategy(manifest, group_index, config)
            } else if spec.disposition == Strategy::Unhandled {
                record_honored_group(&mut manifest.coupling_groups[group_index], spec, false);
                entries.push(report_entry(
                    OverrideScope::Group,
                    Some(group_id.clone()),
                    spec,
                    OverrideOutcome::Honored,
                    None,
                    None,
                ));
                Some(Strategy::Unhandled)
            } else {
                let availability = group_availability(manifest, group_index, spec.disposition);
                if let Some(outcome) = availability {
                    entries.push(report_entry(
                        OverrideScope::Group,
                        Some(group_id.clone()),
                        spec,
                        outcome,
                        Some(if outcome == OverrideOutcome::RejectedNoRecipe {
                            "group strategy has no joint materialization recipe".into()
                        } else {
                            "group strategy inputs were not computed".into()
                        }),
                        None,
                    ));
                    independent_joint_group_strategy(manifest, group_index, config)
                } else {
                    let failures = SharedGuardFailures::from(group_failures(
                        manifest,
                        group_index,
                        spec.disposition,
                    ));
                    if failures.is_empty() {
                        record_honored_group(
                            &mut manifest.coupling_groups[group_index],
                            spec,
                            false,
                        );
                        entries.push(report_entry(
                            OverrideScope::Group,
                            Some(group_id.clone()),
                            spec,
                            OverrideOutcome::Honored,
                            None,
                            None,
                        ));
                        Some(spec.disposition)
                    } else if spec.accept_risk {
                        record_honored_group(
                            &mut manifest.coupling_groups[group_index],
                            spec,
                            true,
                        );
                        entries.push(report_entry(
                            OverrideScope::Group,
                            Some(group_id.clone()),
                            spec,
                            OverrideOutcome::HonoredAcceptedRisk,
                            None,
                            Some(failures.clone()),
                        ));
                        ledger.push(AuditRecord {
                            id: String::new(),
                            kind: "accepted-risk".into(),
                            scope: AuditScope::Group {
                                key: group_id.clone(),
                                extra: Extra::new(),
                            },
                            source: AuditSource::Override,
                            text: spec.reason.clone().unwrap_or_else(|| {
                                format!(
                                    "accepted risk for {} on group {group_id}",
                                    spec.disposition.as_str()
                                )
                            }),
                            witness: None,
                            failures: Some(failures),
                            extra: Extra::new(),
                        });
                        Some(spec.disposition)
                    } else {
                        entries.push(report_entry(
                            OverrideScope::Group,
                            Some(group_id.clone()),
                            spec,
                            OverrideOutcome::Rejected,
                            Some("group strategy guard failed and accept_risk was not set".into()),
                            Some(failures),
                        ));
                        independent_joint_group_strategy(manifest, group_index, config)
                    }
                }
            }
        } else {
            independent_joint_group_strategy(manifest, group_index, config)
        };

        let Some(chosen) = chosen else {
            manifest.coupling_groups[group_index].group_disposition = None;
            manifest.coupling_groups[group_index].group_provenance = None;
            manifest.coupling_groups[group_index].r#override = None;
            continue;
        };
        if override_spec.is_none() {
            manifest.coupling_groups[group_index].group_provenance = Some(GroupProvenance::Cascade);
        }
        manifest.coupling_groups[group_index].group_disposition = Some(chosen);
        for key in member_keys {
            if let Some(global) = manifest.globals.iter_mut().find(|global| global.key == key) {
                let disposition = global
                    .disposition
                    .as_mut()
                    .expect("independent cascade populated disposition");
                disposition.chosen = chosen;
                disposition.r#override = None;
                disposition.provenance = if chosen == disposition.cascade_chosen {
                    DispositionProvenance::Cascade
                } else {
                    DispositionProvenance::GroupConstraint
                };
            }
        }
    }

    for (group, spec) in &overrides.groups {
        if !matched.contains(group) {
            entries.push(report_entry(
                OverrideScope::Group,
                Some(group.clone()),
                spec,
                OverrideOutcome::UnmatchedKey,
                Some("no coupling group has this id".into()),
                None,
            ));
        }
    }
    Ok(())
}

fn record_honored_group(
    group: &mut pangs_manifest::CouplingGroup,
    spec: &OverrideSpec,
    accepted_risk: bool,
) {
    group.group_provenance = Some(if accepted_risk {
        GroupProvenance::OverrideAcceptedRisk
    } else {
        GroupProvenance::Override
    });
    group.r#override = Some(OverrideEcho {
        disposition: spec.disposition,
        accept_risk: spec.accept_risk,
        reason: spec.reason.clone(),
        extra: Extra::new(),
    });
}

/// Select an automatic group representation only when it preserves every independently selected
/// per-global transformation. Once those are excluded, choose the first supported joint strategy
/// in cascade order and apply it uniformly to the group.
fn independent_joint_group_strategy(
    manifest: &Manifest,
    group_index: usize,
    config: &CascadeConfig,
) -> Option<Strategy> {
    let group = &manifest.coupling_groups[group_index];
    for key in &group.members {
        let chosen = manifest
            .globals
            .iter()
            .find(|global| &global.key == key)?
            .disposition
            .as_ref()?
            .cascade_chosen;
        if matches!(
            chosen,
            Strategy::Immutable | Strategy::Atomic | Strategy::Localize
        ) {
            return None;
        }
    }
    config
        .order
        .iter()
        .copied()
        .filter(|strategy| matches!(strategy, Strategy::OnceLock | Strategy::Mutex))
        .find(|strategy| group_failures(manifest, group_index, *strategy).is_empty())
}

fn group_availability(
    manifest: &Manifest,
    group_index: usize,
    strategy: Strategy,
) -> Option<OverrideOutcome> {
    let group = &manifest.coupling_groups[group_index];
    for key in &group.members {
        let Some(global) = manifest.globals.iter().find(|global| &global.key == key) else {
            return Some(OverrideOutcome::RejectedStrategyUnavailable);
        };
        if let Some(outcome) = unavailable_outcome(strategy, &global.facts) {
            return Some(outcome);
        }
    }
    match strategy {
        Strategy::OnceLock => match &group.strategy_support.once_lock {
            None => Some(OverrideOutcome::RejectedStrategyUnavailable),
            Some(OnceLockGroupSupport::Unsupported { .. }) => {
                Some(OverrideOutcome::RejectedNoRecipe)
            }
            Some(_) => None,
        },
        Strategy::Mutex => match &group.strategy_support.mutex {
            Some(certificate) if certificate.is_certified() => None,
            Some(_) => Some(OverrideOutcome::RejectedNoRecipe),
            None => Some(OverrideOutcome::RejectedStrategyUnavailable),
        },
        _ => None,
    }
}

fn group_failures(
    manifest: &Manifest,
    group_index: usize,
    strategy: Strategy,
) -> Vec<GuardFailure> {
    let group = &manifest.coupling_groups[group_index];
    let mut failures = Vec::new();
    for key in &group.members {
        let Some(global) = manifest.globals.iter().find(|global| &global.key == key) else {
            continue;
        };
        match evaluate(strategy, &global.facts) {
            GuardResult::Applicable => {}
            GuardResult::Failed(guards) => {
                failures.extend(guard_failures(key, &global.facts, &guards));
            }
            GuardResult::NotComputed(fact) => failures.push(GuardFailure {
                member: key.clone(),
                guard: fact.into(),
                witness: Witness {
                    kind: "fact-not-computed".into(),
                    site: None,
                    symbol: None,
                    note: Some(fact.into()),
                    extra: Extra::new(),
                },
                extra: Extra::new(),
            }),
        }
    }
    match strategy {
        Strategy::OnceLock => match &group.strategy_support.once_lock {
            Some(OnceLockGroupSupport::Unsupported { witness, .. }) => {
                if let Some(member) = group.members.first() {
                    failures.push(GuardFailure {
                        member: member.clone(),
                        guard: "group_once_lock_common_p".into(),
                        witness: witness.clone(),
                        extra: Extra::new(),
                    });
                }
            }
            None => {
                if let Some(member) = group.members.first() {
                    failures.push(missing_group_failure(member, "group_once_lock_common_p"));
                }
            }
            Some(_) => {}
        },
        Strategy::Mutex => match &group.strategy_support.mutex {
            Some(Certificate::Certified { .. }) => {}
            Some(Certificate::Failed { witnesses, .. }) => {
                if let Some(member) = group.members.first() {
                    failures.extend(witnesses.iter().cloned().map(|witness| GuardFailure {
                        member: member.clone(),
                        guard: "group_mutex_reentrancy".into(),
                        witness,
                        extra: Extra::new(),
                    }));
                }
            }
            None => {
                if let Some(member) = group.members.first() {
                    failures.push(missing_group_failure(member, "group_mutex_reentrancy"));
                }
            }
        },
        _ => {}
    }
    failures.sort_by(|a, b| (a.member.clone(), &a.guard).cmp(&(b.member.clone(), &b.guard)));
    failures
}

fn missing_group_failure(member: &Key, guard: &str) -> GuardFailure {
    GuardFailure {
        member: member.clone(),
        guard: guard.into(),
        witness: Witness {
            kind: "fact-not-computed".into(),
            site: None,
            symbol: None,
            note: Some(guard.into()),
            extra: Extra::new(),
        },
        extra: Extra::new(),
    }
}

fn unavailable_outcome(strategy: Strategy, facts: &Facts) -> Option<OverrideOutcome> {
    let slot = match strategy {
        Strategy::OnceLock => Some(&facts.phase_stationarity),
        Strategy::Atomic => Some(&facts.atomic_eligibility),
        Strategy::Mutex => Some(&facts.mutex_eligibility),
        Strategy::Localize if facts.localization.is_none() => {
            return Some(OverrideOutcome::RejectedStrategyUnavailable)
        }
        _ => None,
    }?;
    match slot {
        None => Some(OverrideOutcome::RejectedStrategyUnavailable),
        Some(value) if !value.has_recipe() => Some(OverrideOutcome::RejectedNoRecipe),
        Some(_) => None,
    }
}

fn honor_override(disposition: &mut Disposition, spec: &OverrideSpec, accepted_risk: bool) {
    disposition.chosen = spec.disposition;
    disposition.provenance = if accepted_risk {
        DispositionProvenance::OverrideAcceptedRisk
    } else {
        DispositionProvenance::Override
    };
    disposition.r#override = Some(OverrideEcho {
        disposition: spec.disposition,
        accept_risk: spec.accept_risk,
        reason: spec.reason.clone(),
        extra: Extra::new(),
    });
}

fn report_entry(
    scope: OverrideScope,
    key: Option<String>,
    spec: &OverrideSpec,
    outcome: OverrideOutcome,
    reason: Option<String>,
    failures: Option<SharedGuardFailures>,
) -> OverrideReportEntry {
    OverrideReportEntry {
        scope,
        key,
        requested: OverrideRequested::Strategy(spec.disposition),
        accept_risk: spec.accept_risk,
        outcome,
        reason,
        witness: None,
        failures,
        extra: Extra::new(),
    }
}

fn count_outcomes(entries: &[OverrideReportEntry]) -> OverrideCounts {
    let mut counts = OverrideCounts::default();
    for entry in entries {
        match entry.outcome {
            OverrideOutcome::Honored => counts.honored += 1,
            OverrideOutcome::HonoredAcceptedRisk => counts.honored_accepted_risk += 1,
            OverrideOutcome::Rejected => counts.rejected += 1,
            OverrideOutcome::RejectedStrategyDisabled => counts.rejected_strategy_disabled += 1,
            OverrideOutcome::RejectedStrategyUnavailable => {
                counts.rejected_strategy_unavailable += 1
            }
            OverrideOutcome::RejectedNoRecipe => counts.rejected_no_recipe += 1,
            OverrideOutcome::UnmatchedKey => counts.unmatched_key += 1,
        }
    }
    counts
}

fn guard_failures(key: &Key, facts: &Facts, guards: &[String]) -> Vec<GuardFailure> {
    let mut failures = guards
        .iter()
        .map(|guard| GuardFailure {
            member: key.clone(),
            guard: guard.clone(),
            witness: witness_for_guard(facts, guard),
            extra: Extra::new(),
        })
        .collect::<Vec<_>>();
    failures.sort_by(|a, b| (a.member.clone(), &a.guard).cmp(&(b.member.clone(), &b.guard)));
    failures
}

fn witness_for_guard(facts: &Facts, guard: &str) -> Witness {
    let evidenced = match guard {
        "written" => facts.written.witness.as_ref(),
        "omega_escaped_address" => facts.omega_escaped_address.witness.as_ref(),
        "violation_taint" => facts.violation_taint.witness.as_ref(),
        _ => None,
    };
    if let Some(witness) = evidenced {
        return witness.clone();
    }
    let certificate = match guard {
        "phase_stationarity" => facts.phase_stationarity.as_ref(),
        "atomic_eligibility" => facts.atomic_eligibility.as_ref(),
        "mutex_eligibility" => facts.mutex_eligibility.as_ref(),
        _ => None,
    };
    if let Some(Certificate::Failed { witnesses, .. }) = certificate {
        if let Some(witness) = witnesses.first() {
            return witness.clone();
        }
    }
    if guard == "localization" {
        if let Some(witness) = facts
            .localization
            .as_ref()
            .and_then(|value| value.blockers.first())
            .map(|blocker| &blocker.witness)
        {
            return witness.clone();
        }
    }
    Witness {
        kind: "guard-failed".into(),
        site: None,
        symbol: None,
        note: Some(format!("{guard} failed without a more specific witness")),
        extra: Extra::new(),
    }
}

pub fn read_ledger(path: &Path) -> Result<Vec<AuditRecord>, DisposeError> {
    if !path.exists() {
        return Err(DisposeError::MissingLedger(path.to_owned()));
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

pub fn regenerate_override_records(records: &mut Vec<AuditRecord>) -> Result<(), DisposeError> {
    records.retain(|record| record.source != AuditSource::Override);
    canonicalize_audit(records)?;
    Ok(())
}

/// Replace the ledger first and the manifest last; the manifest is the pair's commit point.
pub fn write_artifact_pair(
    output_dir: &Path,
    manifest: &Manifest,
    ledger: &[AuditRecord],
) -> Result<(), DisposeError> {
    fs::create_dir_all(output_dir)?;
    write_artifact_pair_to(
        &output_dir.join("pangs-manifest.json"),
        &output_dir.join("pangs-audit.json"),
        manifest,
        ledger,
    )
}

pub fn write_artifact_pair_to(
    manifest_path: &Path,
    ledger_path: &Path,
    manifest: &Manifest,
    ledger: &[AuditRecord],
) -> Result<(), DisposeError> {
    manifest.validate()?;
    let manifest_bytes = to_canonical_json(manifest)?;
    let ledger_bytes = to_canonical_json(&ledger)?;
    let ledger_dir = ledger_path.parent().unwrap_or_else(|| Path::new("."));
    let manifest_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(ledger_dir)?;
    fs::create_dir_all(manifest_dir)?;
    let mut ledger_tmp = NamedTempFile::new_in(ledger_dir)?;
    ledger_tmp.write_all(&ledger_bytes)?;
    ledger_tmp.as_file().sync_all()?;
    let mut manifest_tmp = NamedTempFile::new_in(manifest_dir)?;
    manifest_tmp.write_all(&manifest_bytes)?;
    manifest_tmp.as_file().sync_all()?;
    ledger_tmp
        .persist(ledger_path)
        .map_err(|error| error.error)?;
    manifest_tmp
        .persist(manifest_path)
        .map_err(|error| error.error)?;
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum GuardResult {
    Applicable,
    Failed(Vec<String>),
    NotComputed(&'static str),
}

const LOCALIZE_EXEMPT_VIOLATION_KIND: &str = "fnptr_varargs_internal_unmodeled";

fn violation_taint_blocks(strategy: Strategy, facts: &Facts) -> bool {
    if strategy != Strategy::Localize {
        return facts.violation_taint.value;
    }

    let mut saw_hard = false;
    for diagnostic in &facts.violation_relevance {
        if !diagnostic.classification.is_hard() {
            continue;
        }
        saw_hard = true;
        if diagnostic.finding_kind != LOCALIZE_EXEMPT_VIOLATION_KIND {
            return true;
        }
    }

    // Facts::validate() rejects this mismatch at artifact boundaries. Keep the evaluator
    // independently fail-closed because it is also used directly in unit and policy code.
    facts.violation_taint.value && !saw_hard
}

fn evaluate(strategy: Strategy, facts: &Facts) -> GuardResult {
    if violation_taint_blocks(strategy, facts) {
        let mut failed = vec!["violation_taint".to_owned()];
        match strategy {
            Strategy::Immutable => {
                if facts.written.value {
                    failed.push("written".to_owned());
                }
                if facts.omega_escaped_address.value {
                    failed.push("omega_escaped_address".to_owned());
                }
            }
            Strategy::OnceLock => push_failed_certificate(
                &mut failed,
                "phase_stationarity",
                facts.phase_stationarity.as_ref(),
            ),
            Strategy::Atomic => push_failed_certificate(
                &mut failed,
                "atomic_eligibility",
                facts.atomic_eligibility.as_ref(),
            ),
            Strategy::Mutex => push_failed_certificate(
                &mut failed,
                "mutex_eligibility",
                facts.mutex_eligibility.as_ref(),
            ),
            Strategy::Localize => {
                if facts
                    .localization
                    .as_ref()
                    .is_some_and(|value| value.verdict != LocalizationVerdict::Ok)
                {
                    failed.push("localization".to_owned());
                }
            }
            Strategy::Unhandled => unreachable!("unhandled is not evaluated"),
        }
        return GuardResult::Failed(failed);
    }

    match strategy {
        Strategy::Immutable => {
            let mut failed = Vec::new();
            if facts.written.value {
                failed.push("written".to_owned());
            }
            if facts.omega_escaped_address.value {
                failed.push("omega_escaped_address".to_owned());
            }
            failed_result(failed)
        }
        Strategy::OnceLock => certificate_guard("phase_stationarity", &facts.phase_stationarity),
        Strategy::Atomic => certificate_guard("atomic_eligibility", &facts.atomic_eligibility),
        Strategy::Mutex => certificate_guard("mutex_eligibility", &facts.mutex_eligibility),
        Strategy::Localize => match &facts.localization {
            None => GuardResult::NotComputed("localization"),
            Some(value) if value.verdict == LocalizationVerdict::Ok => GuardResult::Applicable,
            Some(_) => GuardResult::Failed(vec!["localization".to_owned()]),
        },
        Strategy::Unhandled => unreachable!("unhandled is not evaluated"),
    }
}

fn push_failed_certificate(failed: &mut Vec<String>, name: &str, slot: Option<&Certificate>) {
    if !slot.is_some_and(Certificate::is_certified) {
        failed.push(name.to_owned());
    }
}

fn certificate_guard(name: &'static str, slot: &Option<Certificate>) -> GuardResult {
    match slot {
        None => GuardResult::NotComputed(name),
        Some(value) if value.is_certified() => GuardResult::Applicable,
        Some(_) => GuardResult::Failed(vec![name.to_owned()]),
    }
}

fn failed_result(failed: Vec<String>) -> GuardResult {
    if failed.is_empty() {
        GuardResult::Applicable
    } else {
        GuardResult::Failed(failed)
    }
}

#[cfg(test)]
mod tests {
    use pangs_manifest::{
        AnalysisRun, AuditRecord, CouplingGroup, EvidencedBool, GlobalRecord, GroupStrategySupport,
        Linkage, Localization, LocalizationBlocker, Manifest, Meta, RunHeader, UnkeyedGlobal,
        ViolationRelevance, ViolationRelevanceDiagnostic, WordSizedScalar,
    };
    use serde_json::json;

    use super::*;

    fn bool_fact(value: bool) -> EvidencedBool {
        EvidencedBool {
            value,
            witness: None,
            extra: Extra::new(),
        }
    }

    fn base_facts() -> Facts {
        Facts {
            written: bool_fact(false),
            omega_escaped_address: bool_fact(false),
            violation_taint: bool_fact(false),
            thread_visible: bool_fact(false),
            signal_context_access: bool_fact(false),
            access_set_complete: bool_fact(true),
            word_sized_scalar: WordSizedScalar {
                value: false,
                type_spelling: None,
                size_bits: None,
                class: None,
                signed: None,
                extra: Extra::new(),
            },
            phase_stationarity: None,
            atomic_eligibility: None,
            mutex_eligibility: None,
            coupling_group: None,
            localization: None,
            violation_relevance: Vec::new(),
            extra: Extra::new(),
        }
    }

    fn certified() -> Certificate {
        Certificate::Certified {
            certificate: json!({}),
            extra: Extra::new(),
        }
    }

    fn violation_diagnostic(
        classification: ViolationRelevance,
        finding_kind: &str,
    ) -> ViolationRelevanceDiagnostic {
        ViolationRelevanceDiagnostic {
            classification,
            finding_kind: finding_kind.into(),
            witness: Witness {
                kind: "violation-test".into(),
                site: None,
                symbol: Some("g".into()),
                note: None,
                extra: Extra::new(),
            },
        }
    }

    fn ok_localization() -> Localization {
        Localization {
            component: "comp-1".into(),
            verdict: LocalizationVerdict::Ok,
            blockers: Vec::new(),
            extra: Extra::new(),
        }
    }

    #[test]
    fn first_applicable_wins_and_trace_stops() {
        let mut facts = base_facts();
        facts.written.value = true;
        facts.phase_stationarity = Some(certified());
        let config = CascadeConfig::default_for(DisposeMode::Application);
        let (chosen, trace) = cascade(&facts, &config).unwrap();
        assert_eq!(chosen, Strategy::OnceLock);
        assert_eq!(trace.len(), 1);
        assert_eq!(trace[0].strategy, Strategy::Immutable);
    }

    #[test]
    fn null_and_failed_certificate_are_distinct() {
        let mut facts = base_facts();
        facts.written.value = true;
        let config = CascadeConfig {
            mode: DisposeMode::Library,
            order: vec![Strategy::Atomic],
        };
        let (_, trace) = cascade(&facts, &config).unwrap();
        assert!(matches!(
            trace[0].reason,
            SkipReason::FactNotComputed { .. }
        ));

        facts.atomic_eligibility = Some(Certificate::Failed {
            codes: vec!["bad-access".into()],
            witnesses: Vec::new(),
            recipe: None,
            diagnostics: None,
            extra: Extra::new(),
        });
        let (_, trace) = cascade(&facts, &config).unwrap();
        assert!(matches!(trace[0].reason, SkipReason::GuardFailed { .. }));
    }

    #[test]
    fn violation_taint_forces_every_strategy_to_guard_failed() {
        let mut facts = base_facts();
        facts.violation_taint.value = true;
        let config = CascadeConfig::default_for(DisposeMode::Application);
        let (chosen, trace) = cascade(&facts, &config).unwrap();
        assert_eq!(chosen, Strategy::Unhandled);
        assert_eq!(trace.len(), config.order.len());
        for skip in trace {
            let SkipReason::GuardFailed { failed, .. } = skip.reason else {
                panic!("taint must dominate null slots");
            };
            assert_eq!(failed.first().map(String::as_str), Some("violation_taint"));
        }
    }

    #[test]
    fn localize_ignores_only_exempt_hard_vararg_diagnostics() {
        let mut facts = base_facts();
        facts.violation_taint.value = true;
        facts.violation_relevance.push(violation_diagnostic(
            ViolationRelevance::AddressRelevant,
            LOCALIZE_EXEMPT_VIOLATION_KIND,
        ));
        facts.localization = Some(ok_localization());
        let config = CascadeConfig {
            mode: DisposeMode::Application,
            order: vec![Strategy::Localize],
        };
        assert_eq!(cascade(&facts, &config).unwrap().0, Strategy::Localize);

        facts.violation_relevance.push(violation_diagnostic(
            ViolationRelevance::Unresolved,
            "dlopen_dlsym",
        ));
        let (chosen, trace) = cascade(&facts, &config).unwrap();
        assert_eq!(chosen, Strategy::Unhandled);
        assert!(matches!(
            &trace[0].reason,
            SkipReason::GuardFailed { failed, .. }
                if failed.first().map(String::as_str) == Some("violation_taint")
        ));
    }

    #[test]
    fn localize_exemption_remains_fail_closed_for_missing_diagnostics() {
        let mut facts = base_facts();
        facts.violation_taint.value = true;
        facts.localization = Some(ok_localization());
        let config = CascadeConfig {
            mode: DisposeMode::Application,
            order: vec![Strategy::Localize],
        };
        assert_eq!(cascade(&facts, &config).unwrap().0, Strategy::Unhandled);
    }

    #[test]
    fn manifest_validates_taint_diagnostic_equivalence() {
        let mut facts = base_facts();
        facts.violation_taint.value = true;
        facts.violation_taint.witness = Some(Witness {
            kind: "violation-address-relevant".into(),
            site: None,
            symbol: Some("g".into()),
            note: None,
            extra: Extra::new(),
        });
        assert!(facts.validate().is_err());

        facts.violation_relevance.push(violation_diagnostic(
            ViolationRelevance::AddressRelevant,
            LOCALIZE_EXEMPT_VIOLATION_KIND,
        ));
        assert!(facts.validate().is_ok());

        facts.violation_taint.value = false;
        facts.violation_taint.witness = None;
        assert!(facts.validate().is_err());
    }

    #[test]
    fn exempt_taint_does_not_override_blocked_localization_verdict() {
        let mut facts = base_facts();
        facts.violation_taint.value = true;
        facts.violation_relevance.push(violation_diagnostic(
            ViolationRelevance::AccessShapeRelevant,
            LOCALIZE_EXEMPT_VIOLATION_KIND,
        ));
        facts.localization = Some(Localization {
            component: "comp-1".into(),
            verdict: LocalizationVerdict::Blocked,
            blockers: vec![LocalizationBlocker {
                code: "unknown-caller-taint".into(),
                witness: Witness {
                    kind: "unknown-caller-taint".into(),
                    site: None,
                    symbol: Some("target".into()),
                    note: None,
                    extra: Extra::new(),
                },
                extra: Extra::new(),
            }],
            extra: Extra::new(),
        });
        let config = CascadeConfig {
            mode: DisposeMode::Application,
            order: vec![Strategy::Localize],
        };
        let (chosen, trace) = cascade(&facts, &config).unwrap();
        assert_eq!(chosen, Strategy::Unhandled);
        assert!(matches!(
            &trace[0].reason,
            SkipReason::GuardFailed { failed, .. } if failed == &["localization"]
        ));
    }

    #[test]
    fn localization_is_fact_composed() {
        let mut facts = base_facts();
        facts.localization = Some(Localization {
            component: "comp-1".into(),
            verdict: LocalizationVerdict::Ok,
            blockers: Vec::new(),
            extra: Extra::new(),
        });
        let config = CascadeConfig {
            mode: DisposeMode::Application,
            order: vec![Strategy::Localize],
        };
        assert_eq!(cascade(&facts, &config).unwrap().0, Strategy::Localize);
    }

    #[test]
    fn rejects_invalid_orders() {
        assert_eq!(
            CascadeConfig {
                mode: DisposeMode::Library,
                order: vec![Strategy::Localize],
            }
            .validate(),
            Err(ConfigError::LocalizeInLibrary)
        );
        assert_eq!(
            CascadeConfig {
                mode: DisposeMode::Application,
                order: vec![Strategy::Atomic, Strategy::Atomic],
            }
            .validate(),
            Err(ConfigError::Duplicate("atomic".into()))
        );
    }

    #[test]
    fn generated_boolean_grid_preserves_trace_invariant() {
        for written in [false, true] {
            for escaped in [false, true] {
                for tainted in [false, true] {
                    for phase in 0..3 {
                        let mut facts = base_facts();
                        facts.written.value = written;
                        facts.omega_escaped_address.value = escaped;
                        facts.violation_taint.value = tainted;
                        facts.phase_stationarity = match phase {
                            0 => None,
                            1 => Some(certified()),
                            _ => Some(Certificate::Failed {
                                codes: vec!["failed".into()],
                                witnesses: Vec::new(),
                                recipe: None,
                                diagnostics: None,
                                extra: Extra::new(),
                            }),
                        };
                        let config = CascadeConfig::default_for(DisposeMode::Application);
                        let (chosen, trace) = cascade(&facts, &config).unwrap();
                        let chosen_index = config.order.iter().position(|s| *s == chosen);
                        let expected = chosen_index.unwrap_or(config.order.len());
                        assert_eq!(trace.len(), expected);
                        assert!(trace
                            .iter()
                            .zip(&config.order)
                            .all(|(skip, strategy)| { skip.strategy == *strategy }));
                    }
                }
            }
        }
    }

    fn manifest_with(facts: Facts) -> Manifest {
        Manifest {
            schema_version: pangs_manifest::SCHEMA_VERSION,
            run: RunHeader {
                analysis: AnalysisRun {
                    pangs_git: "test".into(),
                    llvm_version: "14".into(),
                    input_path: "test.bc".into(),
                    input_sha256: "00".into(),
                    opts: json!({"build_mode": "executable"}),
                    repo_root: "/repo".into(),
                    target_triple: "x86_64-unknown-linux-gnu".into(),
                    data_layout: "e-p:64:64".into(),
                    supported_atomic_widths: vec![8, 16, 32, 64],
                    entry_spine: None,
                    extra: Extra::new(),
                },
                dispose: None,
                extra: Extra::new(),
            },
            globals: vec![GlobalRecord {
                key: Key::parse("src/a.c::g").unwrap(),
                meta: Meta {
                    linkage: Linkage::Internal,
                    type_spelling: None,
                    size_bits: None,
                    align_bits: None,
                    llvm_name: "g".into(),
                    file: Some("src/a.c".into()),
                    line: Some(1),
                    extra: Extra::new(),
                },
                storage_members: Vec::new(),
                facts,
                disposition: None,
                extra: Extra::new(),
            }],
            synthetic_globals: Vec::new(),
            unkeyed_globals: Vec::<UnkeyedGlobal>::new(),
            coupling_groups: Vec::new(),
            coupling_candidates: Vec::new(),
            override_report: None,
            materialization: None,
            extra: Extra::new(),
        }
    }

    fn global_override(strategy: Strategy, accept_risk: bool) -> Overrides {
        Overrides {
            globals: BTreeMap::from([(
                "src/a.c::g".into(),
                OverrideSpec {
                    disposition: strategy,
                    accept_risk,
                    reason: Some("test".into()),
                },
            )]),
            groups: BTreeMap::new(),
            cascade: None,
        }
    }

    #[test]
    fn override_enablement_and_availability_precede_risk() {
        let mut manifest = manifest_with(base_facts());
        let mut ledger = Vec::<AuditRecord>::new();
        let config = CascadeConfig {
            mode: DisposeMode::Application,
            order: vec![Strategy::Localize],
        };
        let overrides = global_override(Strategy::Atomic, true);
        let outcome = apply_policy(
            &mut manifest,
            &mut ledger,
            &config,
            Some(&overrides),
            None,
            None,
        )
        .unwrap();
        assert!(outcome.override_problems);
        assert_eq!(
            manifest.override_report.as_ref().unwrap().entries[0].outcome,
            OverrideOutcome::RejectedStrategyDisabled
        );

        let mut manifest = manifest_with(base_facts());
        let config = CascadeConfig {
            mode: DisposeMode::Application,
            order: vec![Strategy::Atomic],
        };
        apply_policy(
            &mut manifest,
            &mut ledger,
            &config,
            Some(&overrides),
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            manifest.override_report.as_ref().unwrap().entries[0].outcome,
            OverrideOutcome::RejectedStrategyUnavailable
        );
    }

    #[test]
    fn failed_certificate_needs_recipe_then_accept_risk() {
        let witness = Witness {
            kind: "bad-access".into(),
            site: None,
            symbol: None,
            note: None,
            extra: Extra::new(),
        };
        let mut facts = base_facts();
        facts.atomic_eligibility = Some(Certificate::Failed {
            codes: vec!["bad-access".into()],
            witnesses: vec![witness],
            recipe: Some(json!({"sites": []})),
            diagnostics: None,
            extra: Extra::new(),
        });
        let mut manifest = manifest_with(facts);
        let mut ledger = Vec::<AuditRecord>::new();
        let config = CascadeConfig {
            mode: DisposeMode::Application,
            order: vec![Strategy::Atomic],
        };
        let overrides = global_override(Strategy::Atomic, true);
        let outcome = apply_policy(
            &mut manifest,
            &mut ledger,
            &config,
            Some(&overrides),
            Some("overrides.toml".into()),
            Some("hash".into()),
        )
        .unwrap();
        assert!(!outcome.override_problems);
        let disposition = manifest.globals[0].disposition.as_ref().unwrap();
        assert_eq!(disposition.chosen, Strategy::Atomic);
        assert_eq!(
            disposition.provenance,
            DispositionProvenance::OverrideAcceptedRisk
        );
        assert_eq!(ledger.len(), 1);
        assert!(ledger[0].id.starts_with("ar-"));
    }

    #[test]
    fn unhandled_is_always_pinnable() {
        let mut facts = base_facts();
        facts.violation_taint.value = true;
        let mut manifest = manifest_with(facts);
        let mut ledger = Vec::new();
        let config = CascadeConfig {
            mode: DisposeMode::Application,
            order: Vec::new(),
        };
        let overrides = global_override(Strategy::Unhandled, false);
        let outcome = apply_policy(
            &mut manifest,
            &mut ledger,
            &config,
            Some(&overrides),
            None,
            None,
        )
        .unwrap();
        assert!(!outcome.override_problems);
        assert_eq!(
            manifest.globals[0].disposition.as_ref().unwrap().provenance,
            DispositionProvenance::Override
        );
    }

    fn add_two_member_group(manifest: &mut Manifest) {
        let mut second = manifest.globals[0].clone();
        second.key = Key::parse("src/a.c::h").unwrap();
        second.meta.llvm_name = "h".into();
        second.facts.coupling_group = Some("grp-test".into());
        manifest.globals[0].facts.coupling_group = Some("grp-test".into());
        manifest.globals.push(second);
        manifest.coupling_groups.push(CouplingGroup {
            id: "grp-test".into(),
            members: vec![
                Key::parse("src/a.c::g").unwrap(),
                Key::parse("src/a.c::h").unwrap(),
            ],
            evidence: Vec::new(),
            strategy_support: GroupStrategySupport {
                once_lock: None,
                mutex: None,
                extra: Extra::new(),
            },
            group_disposition: None,
            group_provenance: None,
            r#override: None,
            extra: Extra::new(),
        });
    }

    #[test]
    fn failed_group_mutex_certificate_is_not_available() {
        let mut facts = base_facts();
        facts.written.value = true;
        facts.mutex_eligibility = Some(certified());
        let mut manifest = manifest_with(facts);
        add_two_member_group(&mut manifest);
        manifest.coupling_groups[0].strategy_support.mutex = Some(Certificate::Failed {
            codes: vec!["group-reentrant-access-path".into()],
            witnesses: vec![Witness {
                kind: "mutex-reentrant-access-path".into(),
                site: None,
                symbol: Some("grp-test".into()),
                note: None,
                extra: Extra::new(),
            }],
            recipe: None,
            diagnostics: None,
            extra: Extra::new(),
        });

        assert_eq!(
            group_availability(&manifest, 0, Strategy::Mutex),
            Some(OverrideOutcome::RejectedNoRecipe)
        );
        let failures = group_failures(&manifest, 0, Strategy::Mutex);
        assert!(failures.iter().any(|failure| {
            failure.guard == "group_mutex_reentrancy"
                && failure.witness.kind == "mutex-reentrant-access-path"
        }));
    }

    #[test]
    fn group_pin_is_echoed_once_and_member_conflict_is_rejected() {
        let mut manifest = manifest_with(base_facts());
        add_two_member_group(&mut manifest);
        let mut overrides = Overrides::default();
        overrides.groups.insert(
            "grp-test".into(),
            OverrideSpec {
                disposition: Strategy::Unhandled,
                accept_risk: false,
                reason: Some("opt out together".into()),
            },
        );
        overrides.globals.insert(
            "src/a.c::g".into(),
            OverrideSpec {
                disposition: Strategy::Immutable,
                accept_risk: false,
                reason: None,
            },
        );
        let mut ledger = Vec::new();
        let config = CascadeConfig::default_for(DisposeMode::Application);
        let outcome = apply_policy(
            &mut manifest,
            &mut ledger,
            &config,
            Some(&overrides),
            None,
            None,
        )
        .unwrap();
        assert!(outcome.override_problems);
        let group = &manifest.coupling_groups[0];
        assert_eq!(group.group_disposition, Some(Strategy::Unhandled));
        assert_eq!(group.group_provenance, Some(GroupProvenance::Override));
        assert!(group.r#override.is_some());
        for global in &manifest.globals {
            let disposition = global.disposition.as_ref().unwrap();
            assert_eq!(disposition.chosen, Strategy::Unhandled);
            assert!(disposition.r#override.is_none());
            assert_eq!(
                disposition.provenance,
                DispositionProvenance::GroupConstraint
            );
        }
        assert!(manifest
            .override_report
            .as_ref()
            .unwrap()
            .entries
            .iter()
            .any(|entry| entry.scope == OverrideScope::Global
                && entry.outcome == OverrideOutcome::Rejected));
    }

    #[test]
    fn per_global_atomic_results_do_not_create_a_group_disposition() {
        let mut facts = base_facts();
        facts.written.value = true;
        facts.atomic_eligibility = Some(certified());
        let mut manifest = manifest_with(facts);
        add_two_member_group(&mut manifest);
        let mut ledger = Vec::new();
        let config = CascadeConfig {
            mode: DisposeMode::Application,
            order: vec![Strategy::Atomic],
        };

        apply_policy(&mut manifest, &mut ledger, &config, None, None, None).unwrap();

        assert_eq!(manifest.coupling_groups[0].group_disposition, None);
        assert!(manifest
            .globals
            .iter()
            .all(|global| { global.disposition.as_ref().unwrap().chosen == Strategy::Atomic }));
    }

    #[test]
    fn group_preserves_mixed_independent_immutable_results() {
        let mut manifest = manifest_with(base_facts());
        add_two_member_group(&mut manifest);
        manifest.globals[1].facts.written.value = true;
        let mut ledger = Vec::new();
        let config = CascadeConfig {
            mode: DisposeMode::Application,
            order: vec![Strategy::Immutable],
        };

        apply_policy(&mut manifest, &mut ledger, &config, None, None, None).unwrap();

        assert_eq!(manifest.coupling_groups[0].group_disposition, None);
        assert_eq!(
            manifest.globals[0].disposition.as_ref().unwrap().chosen,
            Strategy::Immutable
        );
        assert_eq!(
            manifest.globals[1].disposition.as_ref().unwrap().chosen,
            Strategy::Unhandled
        );
    }

    #[test]
    fn group_preserves_mixed_independent_localization_results() {
        let mut facts = base_facts();
        facts.written.value = true;
        facts.localization = Some(ok_localization());
        let mut manifest = manifest_with(facts);
        add_two_member_group(&mut manifest);
        manifest.globals[1].facts.localization = None;
        let mut ledger = Vec::new();
        let config = CascadeConfig {
            mode: DisposeMode::Application,
            order: vec![Strategy::Localize],
        };

        apply_policy(&mut manifest, &mut ledger, &config, None, None, None).unwrap();

        assert_eq!(manifest.coupling_groups[0].group_disposition, None);
        assert_eq!(
            manifest.globals[0].disposition.as_ref().unwrap().chosen,
            Strategy::Localize
        );
        assert_eq!(
            manifest.globals[1].disposition.as_ref().unwrap().chosen,
            Strategy::Unhandled
        );
    }

    #[test]
    fn unanimous_mutex_selection_uses_the_joint_group_representation() {
        let mut facts = base_facts();
        facts.written.value = true;
        facts.mutex_eligibility = Some(certified());
        let mut manifest = manifest_with(facts);
        add_two_member_group(&mut manifest);
        manifest.coupling_groups[0].strategy_support.mutex = Some(certified());
        let mut ledger = Vec::new();
        let config = CascadeConfig {
            mode: DisposeMode::Application,
            order: vec![Strategy::Mutex],
        };

        apply_policy(&mut manifest, &mut ledger, &config, None, None, None).unwrap();

        assert_eq!(
            manifest.coupling_groups[0].group_disposition,
            Some(Strategy::Mutex)
        );
        assert!(manifest
            .globals
            .iter()
            .all(|global| { global.disposition.as_ref().unwrap().chosen == Strategy::Mutex }));
    }

    #[test]
    fn supported_joint_mutex_unifies_non_per_global_fallbacks() {
        let mut facts = base_facts();
        facts.written.value = true;
        facts.phase_stationarity = Some(certified());
        facts.mutex_eligibility = Some(certified());
        let mut manifest = manifest_with(facts);
        add_two_member_group(&mut manifest);
        manifest.globals[1].facts.phase_stationarity = None;
        manifest.coupling_groups[0].strategy_support.mutex = Some(certified());
        let mut ledger = Vec::new();
        let config = CascadeConfig {
            mode: DisposeMode::Application,
            order: vec![Strategy::OnceLock, Strategy::Mutex],
        };

        apply_policy(&mut manifest, &mut ledger, &config, None, None, None).unwrap();

        assert_eq!(
            manifest.coupling_groups[0].group_disposition,
            Some(Strategy::Mutex)
        );
        assert_eq!(
            manifest.globals[0]
                .disposition
                .as_ref()
                .unwrap()
                .cascade_chosen,
            Strategy::OnceLock
        );
        assert!(manifest
            .globals
            .iter()
            .all(|global| { global.disposition.as_ref().unwrap().chosen == Strategy::Mutex }));
    }

    #[test]
    fn per_global_strategy_is_rejected_at_group_override_scope() {
        let mut facts = base_facts();
        facts.written.value = true;
        facts.atomic_eligibility = Some(certified());
        let mut manifest = manifest_with(facts);
        add_two_member_group(&mut manifest);
        manifest.globals[1].facts.atomic_eligibility = None;
        let mut overrides = Overrides::default();
        overrides.groups.insert(
            "grp-test".into(),
            OverrideSpec {
                disposition: Strategy::Atomic,
                accept_risk: false,
                reason: None,
            },
        );
        let mut ledger = Vec::new();
        let config = CascadeConfig {
            mode: DisposeMode::Application,
            order: vec![Strategy::Atomic],
        };

        let outcome = apply_policy(
            &mut manifest,
            &mut ledger,
            &config,
            Some(&overrides),
            None,
            None,
        )
        .unwrap();

        assert!(outcome.override_problems);
        assert_eq!(manifest.coupling_groups[0].group_disposition, None);
        assert_eq!(
            manifest.globals[0].disposition.as_ref().unwrap().chosen,
            Strategy::Atomic
        );
        assert_eq!(
            manifest.globals[1].disposition.as_ref().unwrap().chosen,
            Strategy::Unhandled
        );
    }

    #[test]
    fn group_does_not_demote_an_individually_eligible_atomic() {
        let mut facts = base_facts();
        facts.written.value = true;
        facts.atomic_eligibility = Some(certified());
        let mut manifest = manifest_with(facts);
        add_two_member_group(&mut manifest);
        manifest.globals[1].facts.atomic_eligibility = None;
        let mut ledger = Vec::new();
        let config = CascadeConfig {
            mode: DisposeMode::Application,
            order: vec![Strategy::Atomic],
        };

        apply_policy(&mut manifest, &mut ledger, &config, None, None, None).unwrap();

        assert_eq!(manifest.coupling_groups[0].group_disposition, None);
        assert_eq!(
            manifest.globals[0].disposition.as_ref().unwrap().chosen,
            Strategy::Atomic
        );
        assert_eq!(
            manifest.globals[1].disposition.as_ref().unwrap().chosen,
            Strategy::Unhandled
        );
    }

    #[test]
    fn marker_artifacts_follow_final_dispositions() {
        let mut manifest = manifest_with(base_facts());
        let mut ledger = Vec::new();
        let config = CascadeConfig::default_for(DisposeMode::Application);
        apply_policy(&mut manifest, &mut ledger, &config, None, None, None).unwrap();
        let (header, source) = pangs_manifest::marker_artifacts(&manifest).unwrap();
        assert!(header.contains("pangs_disposition_immutable__src_a_c__g__"));
        assert!(source.contains("#include \"pangs_markers.h\""));
        assert!(!header.contains("static inline"));
    }

    #[test]
    fn policy_emits_free_d3_d4_gate_measurements() {
        let mut facts = base_facts();
        facts.written.value = true;
        facts.word_sized_scalar = WordSizedScalar {
            value: true,
            type_spelling: Some("int".into()),
            size_bits: Some(32),
            class: Some(pangs_manifest::ScalarClass::Integer),
            signed: Some(true),
            extra: Extra::new(),
        };
        facts.localization = Some(Localization {
            component: "component-main".into(),
            verdict: LocalizationVerdict::Ok,
            blockers: Vec::new(),
            extra: Extra::new(),
        });
        let mut manifest = manifest_with(facts);
        manifest.globals[0].meta.size_bits = Some(32);
        let mut ledger = Vec::new();
        let config = CascadeConfig::default_for(DisposeMode::Application);
        apply_policy(&mut manifest, &mut ledger, &config, None, None, None).unwrap();

        let report = &manifest.run.dispose.as_ref().unwrap().extra["measurement_report"];
        assert_eq!(report["disposition_distribution"]["localize"], 1);
        assert_eq!(report["disposition_distribution"]["unhandled"], 0);
        assert_eq!(
            report["cascade_skip_histogram"]["immutable"]["guard_failed"]["written"],
            1
        );
        assert_eq!(
            report["cascade_skip_histogram"]["atomic"]["fact_not_computed"]["atomic_eligibility"],
            1
        );
        assert_eq!(
            report["would_be_eligibility"]["atomic"]["free_gate_eligible"],
            1
        );
        assert_eq!(
            report["would_be_eligibility"]["atomic"]["certificate_eligible"],
            0
        );
        assert_eq!(report["would_be_eligibility"]["atomic"]["eligible"], 0);
        assert_eq!(report["would_be_eligibility"]["mutex"]["eligible"], 1);
        assert_eq!(report["context_struct_pressure"]["known_size_bits"], 32);
        assert_eq!(
            report["context_struct_pressure"]["components"]["component-main"]["globals"],
            1
        );
        assert_eq!(report["override_usage"]["honored"], 0);
    }

    #[test]
    fn unused_localization_candidate_does_not_add_context_struct_pressure() {
        let mut facts = base_facts();
        facts.localization = Some(ok_localization());
        let mut manifest = manifest_with(facts);
        manifest.globals[0].meta.size_bits = Some(64);
        let mut ledger = Vec::new();
        let config = CascadeConfig::default_for(DisposeMode::Application);

        apply_policy(&mut manifest, &mut ledger, &config, None, None, None).unwrap();

        let disposition = manifest.globals[0].disposition.as_ref().unwrap();
        assert_eq!(disposition.chosen, Strategy::Immutable);
        let pressure = &manifest.run.dispose.as_ref().unwrap().extra["measurement_report"]
            ["context_struct_pressure"];
        assert_eq!(pressure["localized_globals"], 0);
        assert_eq!(pressure["known_size_bits"], 0);
        assert_eq!(pressure["unknown_size_globals"], 0);
        assert_eq!(pressure["components"], json!({}));
    }
}
