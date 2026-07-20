use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use pangs_pir::{fsa_compatible, Pir, Signature, Stmt};

use crate::CallsiteId;

pub(crate) const DEFAULT_CONTEXT_DEPTH: usize = 8;

#[derive(Debug, Clone)]
pub(crate) struct SimpleIcallQuery {
    pub callsite: CallsiteId,
    pub callsite_key: String,
    pub func_index: usize,
    pub stmt_index: usize,
    pub operand: String,
    pub sig: Signature,
}

#[derive(Debug, Clone)]
pub(crate) struct SimpleIcallResolution {
    pub targets: Vec<String>,
    pub sites: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct SimpleIcallReport {
    pub resolutions: BTreeMap<CallsiteId, SimpleIcallResolution>,
    pub confined_functions: BTreeSet<String>,
}

#[derive(Debug, Clone, Default)]
struct ValueResolution {
    targets: BTreeSet<String>,
    sites: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalkResult {
    Simple,
    Complex,
}

pub(crate) fn resolve_simple_icalls(
    module: &Pir,
    queries: &[SimpleIcallQuery],
    context_depth: usize,
) -> SimpleIcallReport {
    let mut resolver = SimpleResolver::new(module, context_depth);
    let mut resolutions = BTreeMap::new();
    let mut reached_sites: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for query in queries {
        if let Some(resolution) = resolver.resolve_query(query) {
            for target in &resolution.targets {
                let prefix = format!("function:{target}@");
                reached_sites.entry(target.clone()).or_default().extend(
                    resolution
                        .sites
                        .iter()
                        .filter(|site| site.starts_with(&prefix))
                        .cloned(),
                );
            }
            resolutions.insert(query.callsite, resolution);
        }
    }
    let address_taken_sites = resolver.address_taken_sites();
    let confined_functions = module
        .functions
        .iter()
        .filter(|func| func.address_taken)
        .filter_map(|func| {
            let sites = address_taken_sites.get(&func.key)?;
            let reached = reached_sites.get(&func.key)?;
            sites.is_subset(reached).then(|| func.key.clone())
        })
        .collect();
    SimpleIcallReport {
        resolutions,
        confined_functions,
    }
}

struct SimpleResolver<'a> {
    module: &'a Pir,
    context_depth: usize,
    functions: HashMap<&'a str, usize>,
    globals: HashSet<&'a str>,
    definitions: Vec<HashMap<&'a str, usize>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct SubObj {
    root: String,
    byte_off: i64,
}

impl<'a> SimpleResolver<'a> {
    fn new(module: &'a Pir, context_depth: usize) -> Self {
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
            context_depth,
            functions,
            globals,
            definitions,
        }
    }

    fn resolve_query(&mut self, query: &SimpleIcallQuery) -> Option<SimpleIcallResolution> {
        let mut value = ValueResolution::default();
        let mut visiting = HashSet::new();
        if self.resolve_value(
            query.func_index,
            query.stmt_index,
            &query.operand,
            0,
            &mut visiting,
            &mut value,
        ) == WalkResult::Complex
        {
            return None;
        }
        if value.targets.is_empty() {
            return None;
        }
        let mut targets = value.targets.into_iter().collect::<Vec<_>>();
        targets.retain(|target| {
            self.functions
                .get(target.as_str())
                .and_then(|&index| self.module.functions.get(index))
                .map(|func| fsa_compatible(&query.sig, &func.sig))
                .unwrap_or(false)
        });
        targets.sort();
        targets.dedup();
        if targets.is_empty() {
            return None;
        }
        if targets
            .iter()
            .any(|target| self.function_has_unsafe_escape(target))
        {
            return None;
        }
        Some(SimpleIcallResolution {
            targets,
            sites: value.sites.into_iter().collect(),
        })
    }

    fn resolve_value(
        &mut self,
        func_index: usize,
        before_stmt: usize,
        value: &str,
        depth: usize,
        visiting: &mut HashSet<(usize, String, usize)>,
        out: &mut ValueResolution,
    ) -> WalkResult {
        if depth > self.context_depth {
            return WalkResult::Complex;
        }
        if let Some(&target_index) = self.functions.get(value) {
            let target = &self.module.functions[target_index];
            out.targets.insert(target.key.clone());
            out.sites.insert(format!(
                "function:{}@{}",
                target.key,
                self.owner_key(func_index)
            ));
            return WalkResult::Simple;
        }
        if self.globals.contains(value) {
            return self.resolve_global(value, depth, visiting, out);
        }
        if !visiting.insert((func_index, value.to_string(), depth)) {
            return WalkResult::Simple;
        }
        let result = self.resolve_value_inner(func_index, before_stmt, value, depth, visiting, out);
        visiting.remove(&(func_index, value.to_string(), depth));
        result
    }

    fn resolve_value_inner(
        &mut self,
        func_index: usize,
        before_stmt: usize,
        value: &str,
        depth: usize,
        visiting: &mut HashSet<(usize, String, usize)>,
        out: &mut ValueResolution,
    ) -> WalkResult {
        if let Some(param_index) = self.param_index(func_index, value) {
            return self.resolve_param_actuals(func_index, param_index, depth + 1, visiting, out);
        }
        let Some(&stmt_index) = self.definitions[func_index].get(value) else {
            return WalkResult::Complex;
        };
        if stmt_index >= before_stmt {
            return WalkResult::Complex;
        }
        match &self.module.functions[func_index].body[stmt_index] {
            Stmt::Assign { sources, .. } => {
                self.resolve_all_sources(func_index, stmt_index, sources, depth, visiting, out)
            }
            Stmt::ScalarOp { .. } => WalkResult::Complex,
            Stmt::Gep { base, .. } => {
                self.resolve_value(func_index, stmt_index, base, depth, visiting, out)
            }
            Stmt::Load { address, .. } => {
                if let Some(place) = self.function_place(func_index, stmt_index, address) {
                    self.resolve_global_place(&place, depth, visiting, out)
                } else {
                    WalkResult::Complex
                }
            }
            Stmt::CallDirect { callee, .. } => {
                self.resolve_return_values(callee, depth + 1, visiting, out)
            }
            Stmt::Alloca { .. }
            | Stmt::PtrToInt { .. }
            | Stmt::IntToPtr { .. }
            | Stmt::VarArg { .. }
            | Stmt::Memcpy { .. }
            | Stmt::Memset { .. }
            | Stmt::Unknown { .. }
            | Stmt::CallIndirect { .. } => WalkResult::Complex,
            Stmt::Store { .. } | Stmt::Return { .. } | Stmt::GlobalRef { .. } => {
                WalkResult::Complex
            }
        }
    }

    fn resolve_all_sources(
        &mut self,
        func_index: usize,
        before_stmt: usize,
        sources: &[String],
        depth: usize,
        visiting: &mut HashSet<(usize, String, usize)>,
        out: &mut ValueResolution,
    ) -> WalkResult {
        if sources.is_empty() {
            return WalkResult::Complex;
        }
        for source in sources {
            if self.resolve_value(func_index, before_stmt, source, depth, visiting, out)
                == WalkResult::Complex
            {
                return WalkResult::Complex;
            }
        }
        WalkResult::Simple
    }

    fn resolve_return_values(
        &mut self,
        callee: &str,
        depth: usize,
        visiting: &mut HashSet<(usize, String, usize)>,
        out: &mut ValueResolution,
    ) -> WalkResult {
        if depth > self.context_depth {
            return WalkResult::Complex;
        }
        let Some(&callee_index) = self.functions.get(callee) else {
            return WalkResult::Complex;
        };
        let callee_func = &self.module.functions[callee_index];
        if callee_func.external {
            return WalkResult::Complex;
        }
        let mut saw_return = false;
        for (stmt_index, stmt) in callee_func.body.iter().enumerate() {
            if let Stmt::Return {
                value: Some(value), ..
            } = stmt
            {
                saw_return = true;
                if self.resolve_value(callee_index, stmt_index, value, depth, visiting, out)
                    == WalkResult::Complex
                {
                    return WalkResult::Complex;
                }
            }
        }
        if saw_return {
            WalkResult::Simple
        } else {
            WalkResult::Complex
        }
    }

    fn resolve_param_actuals(
        &mut self,
        callee_index: usize,
        param_index: usize,
        depth: usize,
        visiting: &mut HashSet<(usize, String, usize)>,
        out: &mut ValueResolution,
    ) -> WalkResult {
        if depth > self.context_depth {
            return WalkResult::Complex;
        }
        let callee = self.module.functions[callee_index].key.clone();
        let mut saw_call = false;
        for caller_index in 0..self.module.functions.len() {
            let body_len = self.module.functions[caller_index].body.len();
            for stmt_index in 0..body_len {
                let Stmt::CallDirect {
                    callee: called,
                    args,
                    ..
                } = &self.module.functions[caller_index].body[stmt_index]
                else {
                    continue;
                };
                if called != &callee {
                    continue;
                }
                let Some(actual) = args.get(param_index).cloned() else {
                    return WalkResult::Complex;
                };
                saw_call = true;
                if self.resolve_value(caller_index, stmt_index, &actual, depth, visiting, out)
                    == WalkResult::Complex
                {
                    return WalkResult::Complex;
                }
            }
        }
        if saw_call {
            WalkResult::Simple
        } else {
            WalkResult::Complex
        }
    }

    fn resolve_global(
        &mut self,
        global: &str,
        depth: usize,
        visiting: &mut HashSet<(usize, String, usize)>,
        out: &mut ValueResolution,
    ) -> WalkResult {
        self.resolve_global_place(
            &SubObj {
                root: global.to_string(),
                byte_off: 0,
            },
            depth,
            visiting,
            out,
        )
    }

    fn resolve_global_place(
        &mut self,
        place: &SubObj,
        depth: usize,
        visiting: &mut HashSet<(usize, String, usize)>,
        out: &mut ValueResolution,
    ) -> WalkResult {
        if depth > self.context_depth || !self.global_place_is_simple(place) {
            return WalkResult::Complex;
        }
        let mut saw_store = false;
        for func_index in 0..self.module.functions.len() {
            let body_len = self.module.functions[func_index].body.len();
            for stmt_index in 0..body_len {
                let Stmt::Store { address, value, .. } =
                    &self.module.functions[func_index].body[stmt_index]
                else {
                    continue;
                };
                let Some(address_place) = self.function_place(func_index, stmt_index, address)
                else {
                    continue;
                };
                if &address_place != place {
                    continue;
                }
                saw_store = true;
                let value = value.clone();
                if self.resolve_value(func_index, stmt_index, &value, depth, visiting, out)
                    == WalkResult::Complex
                {
                    return WalkResult::Complex;
                }
            }
        }
        for (stmt_index, stmt) in self.module.global_init.iter().enumerate() {
            let Stmt::Store { address, value, .. } = stmt else {
                continue;
            };
            let Some(address_place) = self.global_init_place(stmt_index, address) else {
                continue;
            };
            if &address_place != place {
                continue;
            }
            saw_store = true;
            if self.resolve_global_init_value(stmt_index, value, depth, visiting, out)
                == WalkResult::Complex
            {
                return WalkResult::Complex;
            }
        }
        if saw_store {
            WalkResult::Simple
        } else {
            WalkResult::Complex
        }
    }

    fn resolve_global_init_value(
        &mut self,
        before_stmt: usize,
        value: &str,
        depth: usize,
        visiting: &mut HashSet<(usize, String, usize)>,
        out: &mut ValueResolution,
    ) -> WalkResult {
        if let Some(&target_index) = self.functions.get(value) {
            let target = &self.module.functions[target_index];
            out.targets.insert(target.key.clone());
            out.sites
                .insert(format!("function:{}@global_init", target.key));
            return WalkResult::Simple;
        }
        if self.globals.contains(value) {
            return self.resolve_global(value, depth + 1, visiting, out);
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
                    self.resolve_all_global_init_sources(stmt_index, sources, depth, visiting, out)
                }
                Stmt::Gep { base, .. } => {
                    self.resolve_global_init_value(stmt_index, base, depth, visiting, out)
                }
                _ => WalkResult::Complex,
            };
        }
        WalkResult::Complex
    }

    fn resolve_all_global_init_sources(
        &mut self,
        before_stmt: usize,
        sources: &[String],
        depth: usize,
        visiting: &mut HashSet<(usize, String, usize)>,
        out: &mut ValueResolution,
    ) -> WalkResult {
        if sources.is_empty() {
            return WalkResult::Complex;
        }
        for source in sources {
            if self.resolve_global_init_value(before_stmt, source, depth, visiting, out)
                == WalkResult::Complex
            {
                return WalkResult::Complex;
            }
        }
        WalkResult::Simple
    }

    fn global_is_never_address_taken(&self, global: &str) -> bool {
        if self
            .module
            .globals
            .iter()
            .find(|candidate| candidate.key == global)
            .map(|candidate| candidate.exported)
            .unwrap_or(true)
        {
            return false;
        }
        self.module
            .functions
            .iter()
            .enumerate()
            .all(|(func_index, func)| {
                func.body.iter().enumerate().all(|(stmt_index, stmt)| {
                    self.function_global_use_is_safe(func_index, stmt_index, stmt, global)
                })
            })
            && self
                .module
                .global_init
                .iter()
                .enumerate()
                .all(|(stmt_index, stmt)| {
                    self.global_init_global_use_is_safe(stmt_index, stmt, global)
                })
    }

    fn global_place_is_simple(&self, place: &SubObj) -> bool {
        self.global_is_never_address_taken(&place.root)
    }

    fn function_has_unsafe_escape(&self, target: &str) -> bool {
        let mut visiting = HashSet::new();
        for (func_index, func) in self.module.functions.iter().enumerate() {
            for (stmt_index, stmt) in func.body.iter().enumerate() {
                if self.function_symbol_use_escapes(
                    func_index,
                    stmt_index,
                    stmt,
                    target,
                    0,
                    &mut visiting,
                ) {
                    return true;
                }
            }
        }
        self.module.global_init.iter().any(|stmt| {
            function_use_is_unsafe(stmt, target, |global| {
                self.global_is_never_address_taken(global)
            })
        })
    }

    fn function_symbol_use_escapes(
        &self,
        func_index: usize,
        stmt_index: usize,
        stmt: &Stmt,
        target: &str,
        depth: usize,
        visiting: &mut HashSet<(usize, String, usize)>,
    ) -> bool {
        match stmt {
            Stmt::Assign { dest, sources, .. } if sources.iter().any(|source| source == target) => {
                self.local_value_escapes(func_index, dest, depth, visiting)
            }
            Stmt::ScalarOp { dest, lhs, rhs, .. } if lhs == target || rhs == target => {
                self.local_value_escapes(func_index, dest, depth, visiting)
            }
            Stmt::Store { address, value, .. } if value == target => !self
                .function_place(func_index, stmt_index, address)
                .map(|place| self.global_place_is_simple(&place))
                .unwrap_or_else(|| self.global_is_never_address_taken(address)),
            Stmt::CallDirect {
                callee, sig, args, ..
            } => args.iter().enumerate().any(|(index, arg)| {
                arg == target
                    && self.call_arg_escapes(callee, sig.vararg, index, target, depth, visiting)
            }),
            Stmt::CallIndirect { operand, args, .. } => {
                operand != target && args.iter().any(|arg| arg == target)
            }
            Stmt::Return { value, .. } if value.as_deref() == Some(target) => {
                self.return_value_escapes(func_index, target, depth, visiting)
            }
            Stmt::Load { address, .. } => address == target,
            Stmt::Gep { base, .. } => base == target,
            Stmt::PtrToInt { source, .. } => source == target,
            Stmt::IntToPtr { source, .. } => source == target,
            Stmt::Memcpy { dst, src, .. } => dst == target || src == target,
            Stmt::Memset { dst, value, .. } => dst == target || value == target,
            Stmt::Unknown {
                operands, results, ..
            } => {
                operands.iter().any(|operand| operand == target)
                    || results.iter().any(|result| result == target)
            }
            Stmt::Alloca { .. }
            | Stmt::Assign { .. }
            | Stmt::ScalarOp { .. }
            | Stmt::Store { .. }
            | Stmt::Return { .. }
            | Stmt::VarArg { .. }
            | Stmt::GlobalRef { .. } => false,
        }
    }

    fn local_value_escapes(
        &self,
        func_index: usize,
        value: &str,
        depth: usize,
        visiting: &mut HashSet<(usize, String, usize)>,
    ) -> bool {
        if depth > self.context_depth {
            return true;
        }
        if !visiting.insert((func_index, value.to_string(), depth)) {
            return false;
        }
        let escapes = self.module.functions[func_index]
            .body
            .iter()
            .enumerate()
            .any(|(stmt_index, stmt)| {
                self.local_value_use_escapes(func_index, stmt_index, stmt, value, depth, visiting)
            });
        visiting.remove(&(func_index, value.to_string(), depth));
        escapes
    }

    fn local_value_use_escapes(
        &self,
        func_index: usize,
        stmt_index: usize,
        stmt: &Stmt,
        value: &str,
        depth: usize,
        visiting: &mut HashSet<(usize, String, usize)>,
    ) -> bool {
        match stmt {
            Stmt::Assign { dest, sources, .. } if sources.iter().any(|source| source == value) => {
                self.local_value_escapes(func_index, dest, depth, visiting)
            }
            Stmt::ScalarOp { dest, lhs, rhs, .. } if lhs == value || rhs == value => {
                self.local_value_escapes(func_index, dest, depth, visiting)
            }
            Stmt::Gep { dest, base, .. } if base == value => {
                self.local_value_escapes(func_index, dest, depth, visiting)
            }
            Stmt::Store {
                address,
                value: stored,
                ..
            } if stored == value => !self
                .function_place(func_index, stmt_index, address)
                .map(|place| self.global_place_is_simple(&place))
                .unwrap_or_else(|| self.global_is_never_address_taken(address)),
            Stmt::CallDirect {
                callee, sig, args, ..
            } => args.iter().enumerate().any(|(index, arg)| {
                arg == value
                    && self.call_arg_escapes(callee, sig.vararg, index, value, depth, visiting)
            }),
            Stmt::Return {
                value: Some(ret), ..
            } if ret == value => self.return_value_escapes(func_index, value, depth, visiting),
            Stmt::CallIndirect { operand, args, .. } => {
                operand != value && args.iter().any(|arg| arg == value)
            }
            Stmt::Load { address, .. } => address == value,
            Stmt::Store { address, .. } => address == value,
            Stmt::PtrToInt { source, .. } => source == value,
            Stmt::IntToPtr { source, .. } => source == value,
            Stmt::Memcpy { dst, src, .. } => dst == value || src == value,
            Stmt::Memset {
                dst, value: fill, ..
            } => dst == value || fill == value,
            Stmt::Unknown {
                operands, results, ..
            } => {
                operands.iter().any(|operand| operand == value)
                    || results.iter().any(|result| result == value)
            }
            Stmt::Alloca { .. }
            | Stmt::Assign { .. }
            | Stmt::ScalarOp { .. }
            | Stmt::Gep { .. }
            | Stmt::VarArg { .. }
            | Stmt::Return { .. }
            | Stmt::GlobalRef { .. } => false,
        }
    }

    fn call_arg_escapes(
        &self,
        callee: &str,
        vararg: bool,
        arg_index: usize,
        _value: &str,
        depth: usize,
        visiting: &mut HashSet<(usize, String, usize)>,
    ) -> bool {
        if vararg {
            return true;
        }
        let Some(&callee_index) = self.functions.get(callee) else {
            return true;
        };
        let callee_func = &self.module.functions[callee_index];
        if callee_func.external {
            return true;
        }
        let Some(param) = callee_func.param_names.get(arg_index) else {
            return true;
        };
        self.local_value_escapes(callee_index, param, depth + 1, visiting)
    }

    fn return_value_escapes(
        &self,
        func_index: usize,
        value: &str,
        depth: usize,
        visiting: &mut HashSet<(usize, String, usize)>,
    ) -> bool {
        let func = &self.module.functions[func_index];
        if func.external || func.exported || func.address_taken {
            return true;
        }
        let mut saw_caller = false;
        for caller_index in 0..self.module.functions.len() {
            for stmt in &self.module.functions[caller_index].body {
                let Stmt::CallDirect {
                    callee,
                    dest: Some(dest),
                    ..
                } = stmt
                else {
                    continue;
                };
                if callee != &func.key {
                    continue;
                }
                saw_caller = true;
                if self.local_value_escapes(caller_index, dest, depth + 1, visiting) {
                    return true;
                }
            }
        }
        !saw_caller && !value.is_empty()
    }

    fn address_taken_sites(&self) -> BTreeMap<String, BTreeSet<String>> {
        let mut sites = BTreeMap::<String, BTreeSet<String>>::new();
        for (func_index, func) in self.module.functions.iter().enumerate() {
            for stmt in &func.body {
                for target in function_symbol_value_operands(stmt) {
                    if self.functions.contains_key(target) {
                        sites.entry(target.to_string()).or_default().insert(format!(
                            "function:{}@{}",
                            target,
                            self.owner_key(func_index)
                        ));
                    }
                }
            }
        }
        for stmt in &self.module.global_init {
            for target in function_symbol_value_operands(stmt) {
                if self.functions.contains_key(target) {
                    sites
                        .entry(target.to_string())
                        .or_default()
                        .insert(format!("function:{target}@global_init"));
                }
            }
        }
        sites
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

    fn function_global_use_is_safe(
        &self,
        func_index: usize,
        stmt_index: usize,
        stmt: &Stmt,
        global: &str,
    ) -> bool {
        match stmt {
            Stmt::Load { address, .. } => self
                .function_place(func_index, stmt_index, address)
                .map(|place| place.root == global)
                .unwrap_or_else(|| !operand_mentions_global(address, global)),
            Stmt::Store { address, value, .. } => {
                let address_safe = self
                    .function_place(func_index, stmt_index, address)
                    .map(|place| place.root == global)
                    .unwrap_or_else(|| !operand_mentions_global(address, global));
                address_safe
                    && self
                        .function_place(func_index, stmt_index, value)
                        .map(|place| place.root != global)
                        .unwrap_or_else(|| !operand_mentions_global(value, global))
            }
            Stmt::Gep {
                base,
                byte_off: Some(_),
                ..
            } => self
                .function_place(func_index, stmt_index, base)
                .map(|place| place.root == global)
                .unwrap_or_else(|| !operand_mentions_global(base, global)),
            Stmt::Gep { base, .. } => self
                .function_place(func_index, stmt_index, base)
                .map(|place| place.root != global)
                .unwrap_or_else(|| !operand_mentions_global(base, global)),
            Stmt::GlobalRef { .. } => true,
            _ => stmt_operands(stmt).into_iter().all(|operand| {
                self.function_place(func_index, stmt_index, operand)
                    .map(|place| place.root != global)
                    .unwrap_or_else(|| !operand_mentions_global(operand, global))
            }),
        }
    }

    fn global_init_global_use_is_safe(&self, stmt_index: usize, stmt: &Stmt, global: &str) -> bool {
        match stmt {
            Stmt::Load { address, .. } => self
                .global_init_place(stmt_index, address)
                .map(|place| place.root == global)
                .unwrap_or_else(|| !operand_mentions_global(address, global)),
            Stmt::Store { address, value, .. } => {
                let address_safe = self
                    .global_init_place(stmt_index, address)
                    .map(|place| place.root == global)
                    .unwrap_or_else(|| !operand_mentions_global(address, global));
                address_safe
                    && self
                        .global_init_place(stmt_index, value)
                        .map(|place| place.root != global)
                        .unwrap_or_else(|| !operand_mentions_global(value, global))
            }
            Stmt::Gep {
                base,
                byte_off: Some(_),
                ..
            } => self
                .global_init_place(stmt_index, base)
                .map(|place| place.root == global)
                .unwrap_or_else(|| !operand_mentions_global(base, global)),
            Stmt::Gep { base, .. } => self
                .global_init_place(stmt_index, base)
                .map(|place| place.root != global)
                .unwrap_or_else(|| !operand_mentions_global(base, global)),
            Stmt::GlobalRef { .. } => true,
            _ => stmt_operands(stmt).into_iter().all(|operand| {
                self.global_init_place(stmt_index, operand)
                    .map(|place| place.root != global)
                    .unwrap_or_else(|| !operand_mentions_global(operand, global))
            }),
        }
    }

    fn param_index(&self, func_index: usize, value: &str) -> Option<usize> {
        self.module.functions[func_index]
            .param_names
            .iter()
            .position(|param| param == value)
    }

    fn owner_key(&self, func_index: usize) -> &str {
        self.module
            .functions
            .get(func_index)
            .map(|func| func.key.as_str())
            .unwrap_or("global_init")
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
        Stmt::Unknown { results, .. } => results.first().map(String::as_str),
        Stmt::Store { .. }
        | Stmt::Memcpy { .. }
        | Stmt::Memset { .. }
        | Stmt::Return { .. }
        | Stmt::GlobalRef { .. } => None,
    }
}

fn stmt_operands(stmt: &Stmt) -> Vec<&str> {
    match stmt {
        Stmt::Alloca { .. } | Stmt::VarArg { .. } | Stmt::GlobalRef { .. } => Vec::new(),
        Stmt::Assign { sources, .. } => sources.iter().map(String::as_str).collect(),
        Stmt::ScalarOp { lhs, rhs, .. } => vec![lhs.as_str(), rhs.as_str()],
        Stmt::Load { address, .. } => vec![address.as_str()],
        Stmt::Store { address, value, .. } => vec![address.as_str(), value.as_str()],
        Stmt::Gep { base, .. } => vec![base.as_str()],
        Stmt::PtrToInt { source, .. } | Stmt::IntToPtr { source, .. } => {
            vec![source.as_str()]
        }
        Stmt::Memcpy { dst, src, .. } => vec![dst.as_str(), src.as_str()],
        Stmt::Memset { dst, value, .. } => vec![dst.as_str(), value.as_str()],
        Stmt::Unknown {
            operands, results, ..
        } => operands
            .iter()
            .chain(results.iter())
            .map(String::as_str)
            .collect(),
        Stmt::Return { value, .. } => value.as_deref().into_iter().collect(),
        Stmt::CallDirect { callee, args, .. } => std::iter::once(callee.as_str())
            .chain(args.iter().map(String::as_str))
            .collect(),
        Stmt::CallIndirect { operand, args, .. } => std::iter::once(operand.as_str())
            .chain(args.iter().map(String::as_str))
            .collect(),
    }
}

fn function_symbol_value_operands(stmt: &Stmt) -> Vec<&str> {
    match stmt {
        Stmt::Alloca { .. } | Stmt::VarArg { .. } | Stmt::GlobalRef { .. } => Vec::new(),
        Stmt::Assign { sources, .. } => sources.iter().map(String::as_str).collect(),
        Stmt::ScalarOp { lhs, rhs, .. } => vec![lhs.as_str(), rhs.as_str()],
        Stmt::Load { address, .. } => vec![address.as_str()],
        Stmt::Store { address, value, .. } => vec![address.as_str(), value.as_str()],
        Stmt::Gep { base, .. } => vec![base.as_str()],
        Stmt::PtrToInt { source, .. } | Stmt::IntToPtr { source, .. } => {
            vec![source.as_str()]
        }
        Stmt::Memcpy { dst, src, .. } => vec![dst.as_str(), src.as_str()],
        Stmt::Memset { dst, value, .. } => vec![dst.as_str(), value.as_str()],
        Stmt::Unknown {
            operands, results, ..
        } => operands
            .iter()
            .chain(results.iter())
            .map(String::as_str)
            .collect(),
        Stmt::Return { value, .. } => value.as_deref().into_iter().collect(),
        Stmt::CallDirect { args, .. } => args.iter().map(String::as_str).collect(),
        Stmt::CallIndirect { operand, args, .. } => std::iter::once(operand.as_str())
            .chain(args.iter().map(String::as_str))
            .collect(),
    }
}

fn operand_mentions_global(operand: &str, global: &str) -> bool {
    operand == global
}

fn function_use_is_unsafe<F>(stmt: &Stmt, target: &str, mut global_is_safe_slot: F) -> bool
where
    F: FnMut(&str) -> bool,
{
    match stmt {
        Stmt::Assign { .. } => false,
        Stmt::ScalarOp { dest, lhs, rhs, .. } => dest == target || lhs == target || rhs == target,
        Stmt::Store { address, value, .. } if value == target => {
            !global_is_safe_slot(address.as_str())
        }
        Stmt::Store { .. } => false,
        Stmt::CallIndirect {
            operand,
            args,
            dest,
            ..
        } => {
            args.iter().any(|arg| arg == target)
                || (operand != target && dest.as_deref() == Some(target))
        }
        Stmt::Load { address, .. } => address == target,
        Stmt::Gep { base, .. } => base == target,
        Stmt::PtrToInt { source, .. } => source == target,
        Stmt::IntToPtr { source, .. } => source == target,
        Stmt::Memcpy { dst, src, .. } => dst == target || src == target,
        Stmt::Memset { dst, value, .. } => dst == target || value == target,
        Stmt::Unknown {
            operands, results, ..
        } => {
            operands.iter().any(|operand| operand == target)
                || results.iter().any(|result| result == target)
        }
        Stmt::Return { value, .. } => value.as_deref() == Some(target),
        Stmt::CallDirect {
            callee, args, dest, ..
        } => {
            callee == target
                || dest.as_deref() == Some(target)
                || args.iter().any(|arg| arg == target)
        }
        Stmt::Alloca { dest, .. } => dest == target,
        Stmt::VarArg { dest, .. } => dest == target,
        Stmt::GlobalRef { .. } => false,
    }
}
