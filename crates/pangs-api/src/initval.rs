use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use pangs_pir::{Pir, Stmt};

use crate::simple::{SimpleIcallQuery, SimpleIcallResolution};
use crate::CallsiteId;

#[derive(Debug, Clone, Default)]
pub(crate) struct InitValReport {
    pub resolutions: BTreeMap<CallsiteId, SimpleIcallResolution>,
    pub complete_globals: BTreeSet<String>,
    pub stationary_globals: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct SubObj {
    root: String,
    byte_off: i64,
}

#[derive(Debug, Clone, Default)]
struct SlotValue {
    targets: BTreeSet<String>,
    sites: BTreeSet<String>,
}

pub(crate) fn resolve_initval_icalls(
    module: &Pir,
    queries: &[SimpleIcallQuery],
    stationary_globals: &BTreeSet<String>,
) -> InitValReport {
    let mut resolver = InitValResolver::new(module);
    resolver.build_init_slots();
    let complete_globals = resolver.complete_globals();
    let mut resolutions = BTreeMap::new();
    for query in queries {
        if let Some(resolution) = resolver.resolve_query(query, stationary_globals) {
            resolutions.insert(query.callsite, resolution);
        }
    }
    InitValReport {
        resolutions,
        complete_globals,
        stationary_globals: stationary_globals.clone(),
    }
}

struct InitValResolver<'a> {
    module: &'a Pir,
    functions: HashMap<&'a str, usize>,
    globals: HashSet<&'a str>,
    definitions: Vec<HashMap<&'a str, usize>>,
    init_slots: BTreeMap<SubObj, SlotValue>,
    poisoned_globals: BTreeSet<String>,
}

impl<'a> InitValResolver<'a> {
    fn new(module: &'a Pir) -> Self {
        let functions = module
            .functions
            .iter()
            .enumerate()
            .map(|(index, func)| (func.key.as_str(), index))
            .collect();
        let globals = module
            .globals
            .iter()
            .map(|global| global.key.as_str())
            .collect();
        let definitions = module
            .functions
            .iter()
            .map(|func| {
                let mut defs = HashMap::new();
                for (index, stmt) in func.body.iter().enumerate() {
                    if let Some(dest) = stmt_dest(stmt) {
                        defs.insert(dest, index);
                    }
                }
                defs
            })
            .collect();
        Self {
            module,
            functions,
            globals,
            definitions,
            init_slots: BTreeMap::new(),
            poisoned_globals: BTreeSet::new(),
        }
    }

    fn build_init_slots(&mut self) {
        for (stmt_index, stmt) in self.module.global_init.iter().enumerate() {
            match stmt {
                Stmt::Store { address, value, .. } => {
                    let Some(place) = self.global_init_place(stmt_index, address) else {
                        self.poison_mentioned_globals(stmt);
                        continue;
                    };
                    let Some(value) = self.resolve_global_init_value(stmt_index, value) else {
                        self.poisoned_globals.insert(place.root);
                        continue;
                    };
                    self.init_slots.insert(place, value);
                }
                Stmt::Unknown { .. }
                | Stmt::PtrToInt { .. }
                | Stmt::IntToPtr { .. }
                | Stmt::Memcpy { .. }
                | Stmt::Memset { .. }
                | Stmt::CallDirect { .. }
                | Stmt::CallIndirect { .. } => self.poison_mentioned_globals(stmt),
                Stmt::Gep {
                    base,
                    byte_off: None,
                    ..
                } => {
                    if let Some(place) = self.global_init_place(stmt_index, base) {
                        self.poisoned_globals.insert(place.root);
                    } else {
                        self.poison_mentioned_globals(stmt);
                    }
                }
                _ => {}
            }
        }
    }

    fn complete_globals(&self) -> BTreeSet<String> {
        self.init_slots
            .keys()
            .map(|place| place.root.clone())
            .filter(|global| !self.poisoned_globals.contains(global))
            .collect()
    }

    fn resolve_query(
        &self,
        query: &SimpleIcallQuery,
        stationary_globals: &BTreeSet<String>,
    ) -> Option<SimpleIcallResolution> {
        let value = self.resolve_function_value(
            query.func_index,
            query.stmt_index,
            &query.operand,
            stationary_globals,
            &mut HashSet::new(),
        )?;
        if value.targets.is_empty() {
            return None;
        }
        let mut targets = value.targets.into_iter().collect::<Vec<_>>();
        targets.sort();
        targets.dedup();
        Some(SimpleIcallResolution {
            targets,
            sites: value.sites.into_iter().collect(),
        })
    }

    fn resolve_function_value(
        &self,
        func_index: usize,
        before_stmt: usize,
        value: &str,
        stationary_globals: &BTreeSet<String>,
        visiting: &mut HashSet<(usize, String)>,
    ) -> Option<SlotValue> {
        let key = (func_index, value.to_string());
        if !visiting.insert(key.clone()) {
            return None;
        }
        let stmt_index = *self.definitions.get(func_index)?.get(value)?;
        if stmt_index >= before_stmt {
            visiting.remove(&key);
            return None;
        }
        let result = match &self.module.functions[func_index].body[stmt_index] {
            Stmt::Assign { sources, .. } => self.resolve_all_function_sources(
                func_index,
                stmt_index,
                sources,
                stationary_globals,
                visiting,
            ),
            Stmt::Load { address, .. } => {
                let place = self.function_place(func_index, stmt_index, address)?;
                if !stationary_globals.contains(&place.root) {
                    None
                } else {
                    self.init_slots.get(&place).cloned()
                }
            }
            _ => None,
        };
        visiting.remove(&key);
        result
    }

    fn resolve_all_function_sources(
        &self,
        func_index: usize,
        before_stmt: usize,
        sources: &[String],
        stationary_globals: &BTreeSet<String>,
        visiting: &mut HashSet<(usize, String)>,
    ) -> Option<SlotValue> {
        if sources.is_empty() {
            return None;
        }
        let mut out = SlotValue::default();
        for source in sources {
            let value = self.resolve_function_value(
                func_index,
                before_stmt,
                source,
                stationary_globals,
                visiting,
            )?;
            out.targets.extend(value.targets);
            out.sites.extend(value.sites);
        }
        Some(out)
    }

    fn resolve_global_init_value(&self, before_stmt: usize, value: &str) -> Option<SlotValue> {
        if let Some(&target_index) = self.functions.get(value) {
            let target = &self.module.functions[target_index];
            let mut out = SlotValue::default();
            out.targets.insert(target.key.clone());
            out.sites
                .insert(format!("function:{}@global_init", target.key));
            return Some(out);
        }
        for stmt_index in (0..before_stmt).rev() {
            let Some(dest) = stmt_dest(&self.module.global_init[stmt_index]) else {
                continue;
            };
            if dest != value {
                continue;
            }
            return match &self.module.global_init[stmt_index] {
                Stmt::Assign { sources, .. } => {
                    self.resolve_all_global_init_sources(stmt_index, sources)
                }
                Stmt::Gep { base, .. } => self.resolve_global_init_value(stmt_index, base),
                _ => None,
            };
        }
        None
    }

    fn resolve_all_global_init_sources(
        &self,
        before_stmt: usize,
        sources: &[String],
    ) -> Option<SlotValue> {
        if sources.is_empty() {
            return None;
        }
        let mut out = SlotValue::default();
        for source in sources {
            let value = self.resolve_global_init_value(before_stmt, source)?;
            out.targets.extend(value.targets);
            out.sites.extend(value.sites);
        }
        Some(out)
    }

    fn function_place(&self, func_index: usize, before_stmt: usize, value: &str) -> Option<SubObj> {
        if self.globals.contains(value) {
            return Some(SubObj {
                root: value.to_string(),
                byte_off: 0,
            });
        }
        let stmt_index = *self.definitions.get(func_index)?.get(value)?;
        if stmt_index >= before_stmt {
            return None;
        }
        match &self.module.functions[func_index].body[stmt_index] {
            Stmt::Gep {
                base,
                byte_off: Some(byte_off),
                ..
            } => {
                let mut base = self.function_place(func_index, stmt_index, base)?;
                base.byte_off = base.byte_off.checked_add(*byte_off)?;
                Some(base)
            }
            Stmt::Assign { sources, .. } if sources.len() == 1 => {
                self.function_place(func_index, stmt_index, &sources[0])
            }
            _ => None,
        }
    }

    fn global_init_place(&self, before_stmt: usize, value: &str) -> Option<SubObj> {
        if self.globals.contains(value) {
            return Some(SubObj {
                root: value.to_string(),
                byte_off: 0,
            });
        }
        for stmt_index in (0..before_stmt).rev() {
            let Some(dest) = stmt_dest(&self.module.global_init[stmt_index]) else {
                continue;
            };
            if dest != value {
                continue;
            }
            return match &self.module.global_init[stmt_index] {
                Stmt::Gep {
                    base,
                    byte_off: Some(byte_off),
                    ..
                } => {
                    let mut base = self.global_init_place(stmt_index, base)?;
                    base.byte_off = base.byte_off.checked_add(*byte_off)?;
                    Some(base)
                }
                Stmt::Assign { sources, .. } if sources.len() == 1 => {
                    self.global_init_place(stmt_index, &sources[0])
                }
                _ => None,
            };
        }
        None
    }

    fn poison_mentioned_globals(&mut self, stmt: &Stmt) {
        let globals = self.mentioned_globals(stmt);
        self.poisoned_globals.extend(globals);
    }

    fn mentioned_globals(&self, stmt: &Stmt) -> BTreeSet<String> {
        stmt_operands(stmt)
            .into_iter()
            .filter(|operand| self.globals.contains(*operand))
            .map(str::to_string)
            .collect()
    }
}

fn stmt_dest(stmt: &Stmt) -> Option<&str> {
    match stmt {
        Stmt::Alloca { dest, .. }
        | Stmt::Assign { dest, .. }
        | Stmt::Load { dest, .. }
        | Stmt::Gep { dest, .. }
        | Stmt::PtrToInt { dest, .. }
        | Stmt::IntToPtr { dest, .. } => Some(dest),
        Stmt::CallDirect { dest, .. } | Stmt::CallIndirect { dest, .. } => dest.as_deref(),
        _ => None,
    }
}

fn stmt_operands(stmt: &Stmt) -> Vec<&str> {
    match stmt {
        Stmt::Alloca { .. } => Vec::new(),
        Stmt::Assign { sources, .. } => sources.iter().map(String::as_str).collect(),
        Stmt::Load { address, .. } => vec![address.as_str()],
        Stmt::Store { address, value, .. } => vec![address.as_str(), value.as_str()],
        Stmt::Gep { base, .. } => vec![base.as_str()],
        Stmt::PtrToInt { source, .. } | Stmt::IntToPtr { source, .. } => vec![source.as_str()],
        Stmt::Memcpy { dst, src, .. } => vec![dst.as_str(), src.as_str()],
        Stmt::Memset { dst, value, .. } => vec![dst.as_str(), value.as_str()],
        Stmt::Unknown {
            operands, results, ..
        } => operands
            .iter()
            .chain(results.iter())
            .map(String::as_str)
            .collect(),
        Stmt::Return { value, .. } => value.iter().map(String::as_str).collect(),
        Stmt::CallDirect { args, .. } => args.iter().map(String::as_str).collect(),
        Stmt::CallIndirect { operand, args, .. } => std::iter::once(operand.as_str())
            .chain(args.iter().map(String::as_str))
            .collect(),
        Stmt::GlobalRef { global, .. } => vec![global.as_str()],
    }
}
