use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use pangs_pir::{Pir, Stmt};

use crate::simple::{SimpleIcallQuery, SimpleIcallResolution};
use crate::{CallsiteId, InitValDiagnostic};

#[derive(Debug, Clone, Default)]
pub(crate) struct InitValReport {
    pub resolutions: BTreeMap<CallsiteId, SimpleIcallResolution>,
    pub complete_globals: BTreeSet<String>,
    pub initval_stable_globals: BTreeSet<String>,
    pub diagnostics: BTreeMap<String, Vec<InitValDiagnostic>>,
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
    initval_stable_globals: &BTreeSet<String>,
) -> InitValReport {
    let mut resolver = InitValResolver::new(module);
    resolver.build_init_slots();
    let complete_globals = resolver.complete_globals();
    let mut resolutions = BTreeMap::new();
    for query in queries {
        if let Some(resolution) = resolver.resolve_query(query, initval_stable_globals) {
            resolutions.insert(query.callsite, resolution);
        }
    }
    InitValReport {
        resolutions,
        complete_globals,
        initval_stable_globals: initval_stable_globals.clone(),
        diagnostics: resolver.diagnostics,
    }
}

struct InitValResolver<'a> {
    module: &'a Pir,
    functions: HashMap<&'a str, usize>,
    globals: HashSet<&'a str>,
    definitions: Vec<HashMap<&'a str, usize>>,
    global_init_definitions: HashMap<&'a str, Vec<usize>>,
    init_slots: BTreeMap<SubObj, SlotValue>,
    poisoned_globals: BTreeSet<String>,
    diagnostics: BTreeMap<String, Vec<InitValDiagnostic>>,
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
        let mut global_init_definitions: HashMap<&str, Vec<usize>> = HashMap::new();
        for (index, stmt) in module.global_init.iter().enumerate() {
            if let Some(dest) = stmt_dest(stmt) {
                global_init_definitions.entry(dest).or_default().push(index);
            }
        }
        Self {
            module,
            functions,
            globals,
            definitions,
            global_init_definitions,
            init_slots: BTreeMap::new(),
            poisoned_globals: BTreeSet::new(),
            diagnostics: BTreeMap::new(),
        }
    }

    fn build_init_slots(&mut self) {
        for (stmt_index, stmt) in self.module.global_init.iter().enumerate() {
            match stmt {
                Stmt::Store { address, value, .. } => {
                    let Some(place) = self.global_init_place(stmt_index, address) else {
                        self.poison_mentioned_globals(stmt, "store_address_unresolved", stmt_index);
                        continue;
                    };
                    let Some(value) = self.resolve_global_init_value(stmt_index, value) else {
                        self.poison_global(place.root, "store_value_unresolved", stmt_index);
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
                | Stmt::CallIndirect { .. } => {
                    self.poison_mentioned_globals(stmt, unsupported_stmt_reason(stmt), stmt_index)
                }
                Stmt::Gep {
                    base,
                    byte_off: None,
                    ..
                } => {
                    if let Some(place) = self.global_init_place(stmt_index, base) {
                        self.poison_global(place.root, "dynamic_initializer_gep", stmt_index);
                    } else {
                        self.poison_mentioned_globals(stmt, "dynamic_initializer_gep", stmt_index);
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
        initval_stable_globals: &BTreeSet<String>,
    ) -> Option<SimpleIcallResolution> {
        let value = self.resolve_function_value(
            query.func_index,
            query.stmt_index,
            &query.operand,
            initval_stable_globals,
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
        initval_stable_globals: &BTreeSet<String>,
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
                initval_stable_globals,
                visiting,
            ),
            Stmt::Load { address, .. } => {
                let place = self.function_place(func_index, stmt_index, address)?;
                if !initval_stable_globals.contains(&place.root) {
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
        initval_stable_globals: &BTreeSet<String>,
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
                initval_stable_globals,
                visiting,
            )?;
            out.targets.extend(value.targets);
            out.sites.extend(value.sites);
        }
        Some(out)
    }

    fn resolve_global_init_value(&self, before_stmt: usize, value: &str) -> Option<SlotValue> {
        // LLVM constants retain their `@` sigil in global initializers, while PIR function
        // keys do not.  Global lookup already accepts both spellings; function constants must
        // do the same or aggregate callback tables are spuriously incomplete.
        let symbol = value.strip_prefix('@').unwrap_or(value);
        if let Some(&target_index) = self.functions.get(symbol) {
            let target = &self.module.functions[target_index];
            let mut out = SlotValue::default();
            out.targets.insert(target.key.clone());
            out.sites
                .insert(format!("function:{}@global_init", target.key));
            return Some(out);
        }
        if let Some(global) = self.global_key(value) {
            let mut out = SlotValue::default();
            out.sites.insert(format!("global:{global}@global_init"));
            return Some(out);
        }
        let stmt_index = self.global_init_definition_before(before_stmt, value)?;
        match &self.module.global_init[stmt_index] {
            Stmt::Assign { sources, .. } => {
                self.resolve_all_global_init_sources(stmt_index, sources)
            }
            Stmt::Gep { base, .. } => self.resolve_global_init_value(stmt_index, base),
            _ => None,
        }
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
        if let Some(global) = self.global_key(value) {
            return Some(SubObj {
                root: global.to_string(),
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
        if let Some(global) = self.global_key(value) {
            return Some(SubObj {
                root: global.to_string(),
                byte_off: 0,
            });
        }
        let stmt_index = self.global_init_definition_before(before_stmt, value)?;
        match &self.module.global_init[stmt_index] {
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
        }
    }

    fn global_init_definition_before(&self, before_stmt: usize, value: &str) -> Option<usize> {
        let definitions = self.global_init_definitions.get(value)?;
        let index = definitions.partition_point(|&stmt_index| stmt_index < before_stmt);
        index.checked_sub(1).map(|index| definitions[index])
    }

    fn poison_mentioned_globals(&mut self, stmt: &Stmt, reason: &str, stmt_index: usize) {
        let globals = self.mentioned_globals(stmt);
        for global in globals {
            self.poison_global(global, reason, stmt_index);
        }
    }

    fn poison_global(&mut self, global: String, reason: &str, stmt_index: usize) {
        self.poisoned_globals.insert(global.clone());
        self.diagnostics
            .entry(global)
            .or_default()
            .push(InitValDiagnostic {
                reason: reason.to_string(),
                witness: Some(format!("global_init#{stmt_index}")),
            });
    }

    fn mentioned_globals(&self, stmt: &Stmt) -> BTreeSet<String> {
        stmt_operands(stmt)
            .into_iter()
            .filter_map(|operand| self.global_key(operand).map(str::to_string))
            .collect()
    }

    fn global_key<'b>(&self, operand: &'b str) -> Option<&'b str> {
        if self.globals.contains(operand) {
            return Some(operand);
        }
        let stripped = operand.strip_prefix('@')?;
        self.globals.contains(stripped).then_some(stripped)
    }
}

fn unsupported_stmt_reason(stmt: &Stmt) -> &'static str {
    match stmt {
        Stmt::Unknown { .. } => "unsupported_initializer_unknown",
        Stmt::PtrToInt { .. } => "unsupported_initializer_ptrtoint",
        Stmt::IntToPtr { .. } => "unsupported_initializer_inttoptr",
        Stmt::Memcpy { .. } => "unsupported_initializer_memcpy",
        Stmt::Memset { .. } => "unsupported_initializer_memset",
        Stmt::CallDirect { .. } => "unsupported_initializer_direct_call",
        Stmt::CallIndirect { .. } => "unsupported_initializer_indirect_call",
        _ => "unsupported_initializer_stmt",
    }
}

fn stmt_dest(stmt: &Stmt) -> Option<&str> {
    match stmt {
        Stmt::Alloca { dest, .. }
        | Stmt::Assign { dest, .. }
        | Stmt::ScalarOp { dest, .. }
        | Stmt::Load { dest, .. }
        | Stmt::Gep { dest, .. }
        | Stmt::PtrToInt { dest, .. }
        | Stmt::IntToPtr { dest, .. }
        | Stmt::VarArg { dest, .. } => Some(dest),
        Stmt::CallDirect { dest, .. } | Stmt::CallIndirect { dest, .. } => dest.as_deref(),
        _ => None,
    }
}

fn stmt_operands(stmt: &Stmt) -> Vec<&str> {
    match stmt {
        Stmt::Alloca { .. } => Vec::new(),
        Stmt::Assign { sources, .. } => sources.iter().map(String::as_str).collect(),
        Stmt::ScalarOp { lhs, rhs, .. } => vec![lhs.as_str(), rhs.as_str()],
        Stmt::Load { address, .. } => vec![address.as_str()],
        Stmt::Store { address, value, .. } => vec![address.as_str(), value.as_str()],
        Stmt::Gep { base, .. } => vec![base.as_str()],
        Stmt::PtrToInt { source, .. } | Stmt::IntToPtr { source, .. } => vec![source.as_str()],
        Stmt::VarArg { .. } => Vec::new(),
        Stmt::VaStart { list, .. } | Stmt::VaEnd { list, .. } => vec![list.as_str()],
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
