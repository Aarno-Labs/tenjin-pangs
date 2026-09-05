use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use pangs_pir::{fsa_compatible, Pir, Signature, Stmt};

use crate::{BuildMode, CallsiteId};

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
    build_mode: BuildMode,
    exports: &BTreeSet<String>,
) -> SimpleIcallReport {
    let mut resolver = SimpleResolver::new(module, context_depth, build_mode, exports);
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
    global_init_definitions: HashMap<&'a str, Vec<usize>>,
    reachable: Vec<bool>,
    externally_callable: Vec<bool>,
    externally_writable_globals: HashSet<String>,
    preanalysis: SimplePreanalysis<'a>,
    function_escape_cache: RefCell<HashMap<String, bool>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct SubObj {
    root: String,
    byte_off: i64,
}

#[derive(Debug, Clone, Copy)]
struct ActualSite<'a> {
    caller_index: usize,
    stmt_index: usize,
    actual: &'a str,
}

#[derive(Debug, Clone, Copy)]
enum StoreSite {
    Function {
        func_index: usize,
        stmt_index: usize,
    },
    GlobalInit {
        stmt_index: usize,
    },
}

#[derive(Debug, Clone, Copy)]
enum SymbolUseSite {
    Function {
        func_index: usize,
        stmt_index: usize,
    },
    GlobalInit {
        stmt_index: usize,
    },
}

#[derive(Debug, Clone, Copy)]
struct ReturnConsumer<'a> {
    caller_index: usize,
    dest: &'a str,
}

/// Query-facing relationships materialized by one pass over the PIR. Function indices preserve
/// module order, so indexed walks retain the previous scan order and deterministic witnesses.
struct SimplePreanalysis<'a> {
    direct_call_count: Vec<usize>,
    direct_actuals: HashMap<(usize, usize), Vec<ActualSite<'a>>>,
    stores_by_place: HashMap<SubObj, Vec<StoreSite>>,
    function_symbol_uses: Vec<Vec<SymbolUseSite>>,
    local_uses: Vec<HashMap<&'a str, Vec<usize>>>,
    return_consumers: Vec<Vec<ReturnConsumer<'a>>>,
    address_taken_sites: BTreeMap<String, BTreeSet<String>>,
    unsafe_globals: HashSet<String>,
}

impl SimplePreanalysis<'_> {
    fn empty(function_count: usize) -> Self {
        Self {
            direct_call_count: vec![0; function_count],
            direct_actuals: HashMap::new(),
            stores_by_place: HashMap::new(),
            function_symbol_uses: vec![Vec::new(); function_count],
            local_uses: vec![HashMap::new(); function_count],
            return_consumers: vec![Vec::new(); function_count],
            address_taken_sites: BTreeMap::new(),
            unsafe_globals: HashSet::new(),
        }
    }
}

impl<'a> SimpleResolver<'a> {
    fn new(
        module: &'a Pir,
        context_depth: usize,
        build_mode: BuildMode,
        exports: &BTreeSet<String>,
    ) -> Self {
        let functions = module
            .functions
            .iter()
            .enumerate()
            .map(|(index, func)| (canonical_symbol(&func.key), index))
            .collect();
        let globals = module
            .globals
            .iter()
            .map(|global| canonical_symbol(&global.key))
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
        let mut global_init_definitions = HashMap::<&str, Vec<usize>>::new();
        for (index, stmt) in module.global_init.iter().enumerate() {
            if let Some(dest) = stmt_dest(stmt) {
                global_init_definitions.entry(dest).or_default().push(index);
            }
        }
        let externally_callable = module
            .functions
            .iter()
            .map(|func| {
                func.external
                    || exports.iter().any(|name| same_symbol(name, &func.key))
                    || match build_mode {
                        BuildMode::Library => func.exported,
                        BuildMode::Executable => canonical_symbol(&func.key) == "main",
                    }
            })
            .collect::<Vec<_>>();
        let reachable = reachable_functions(module, build_mode, &externally_callable);
        let externally_writable_globals = module
            .globals
            .iter()
            .filter(|global| {
                exports.iter().any(|name| same_symbol(name, &global.key))
                    || (build_mode == BuildMode::Library && global.exported)
            })
            .map(|global| canonical_symbol(&global.key).to_string())
            .collect();
        let mut resolver = Self {
            module,
            context_depth,
            functions,
            globals,
            definitions,
            global_init_definitions,
            reachable,
            externally_callable,
            externally_writable_globals,
            preanalysis: SimplePreanalysis::empty(module.functions.len()),
            function_escape_cache: RefCell::new(HashMap::new()),
        };
        resolver.preanalysis = resolver.build_preanalysis();
        resolver
    }

    fn build_preanalysis(&self) -> SimplePreanalysis<'a> {
        let module: &'a Pir = self.module;
        let mut index = SimplePreanalysis::empty(module.functions.len());

        for (func_index, func) in module.functions.iter().enumerate() {
            for (stmt_index, stmt) in func.body.iter().enumerate() {
                for operand in stmt_operands(stmt) {
                    index.local_uses[func_index]
                        .entry(operand)
                        .or_default()
                        .push(stmt_index);
                }

                if let Stmt::CallDirect {
                    callee, args, dest, ..
                } = stmt
                {
                    if let Some(callee_index) = self.exact_function_index(callee) {
                        if self.reachable[func_index] {
                            index.direct_call_count[callee_index] += 1;
                            for (param_index, actual) in args.iter().enumerate() {
                                index
                                    .direct_actuals
                                    .entry((callee_index, param_index))
                                    .or_default()
                                    .push(ActualSite {
                                        caller_index: func_index,
                                        stmt_index,
                                        actual,
                                    });
                            }
                        }
                        if let Some(dest) = dest {
                            index.return_consumers[callee_index].push(ReturnConsumer {
                                caller_index: func_index,
                                dest,
                            });
                        }
                    }
                }

                if self.reachable[func_index] {
                    if let Stmt::Store { address, .. } = stmt {
                        if let Some(place) = self.function_place(func_index, stmt_index, address) {
                            index.stores_by_place.entry(place).or_default().push(
                                StoreSite::Function {
                                    func_index,
                                    stmt_index,
                                },
                            );
                        }
                    }
                    self.record_function_unsafe_globals(
                        func_index,
                        stmt_index,
                        stmt,
                        &mut index.unsafe_globals,
                    );
                }

                let mut target_indices = Vec::new();
                for operand in function_symbol_value_operands(stmt) {
                    if let Some(&target_index) = self.functions.get(canonical_symbol(operand)) {
                        if !target_indices.contains(&target_index) {
                            target_indices.push(target_index);
                        }
                    }
                }
                for target_index in target_indices {
                    let target = &module.functions[target_index].key;
                    index
                        .address_taken_sites
                        .entry(target.clone())
                        .or_default()
                        .insert(format!("function:{target}@{}", self.owner_key(func_index)));
                    if self.reachable[func_index] {
                        index.function_symbol_uses[target_index].push(SymbolUseSite::Function {
                            func_index,
                            stmt_index,
                        });
                    }
                }
            }
        }

        for (stmt_index, stmt) in module.global_init.iter().enumerate() {
            if let Stmt::Store { address, .. } = stmt {
                if let Some(place) = self.global_init_place(stmt_index, address) {
                    index
                        .stores_by_place
                        .entry(place)
                        .or_default()
                        .push(StoreSite::GlobalInit { stmt_index });
                }
            }
            self.record_global_init_unsafe_globals(stmt_index, stmt, &mut index.unsafe_globals);

            let mut address_target_indices = Vec::new();
            for operand in function_symbol_value_operands(stmt) {
                if let Some(&target_index) = self.functions.get(canonical_symbol(operand)) {
                    if !address_target_indices.contains(&target_index) {
                        address_target_indices.push(target_index);
                    }
                }
            }
            for target_index in address_target_indices {
                let target = &module.functions[target_index].key;
                index
                    .address_taken_sites
                    .entry(target.clone())
                    .or_default()
                    .insert(format!("function:{target}@global_init"));
            }

            let mut escape_target_indices = Vec::new();
            for operand in global_init_function_escape_operands(stmt) {
                if let Some(&target_index) = self.functions.get(canonical_symbol(operand)) {
                    if !escape_target_indices.contains(&target_index) {
                        escape_target_indices.push(target_index);
                    }
                }
            }
            for target_index in escape_target_indices {
                index.function_symbol_uses[target_index]
                    .push(SymbolUseSite::GlobalInit { stmt_index });
            }
        }

        index
    }

    fn exact_function_index(&self, callee: &str) -> Option<usize> {
        let &index = self.functions.get(canonical_symbol(callee))?;
        (self.module.functions[index].key == callee).then_some(index)
    }

    fn record_function_unsafe_globals(
        &self,
        func_index: usize,
        stmt_index: usize,
        stmt: &Stmt,
        unsafe_globals: &mut HashSet<String>,
    ) {
        match stmt {
            Stmt::Load { address, .. } => {
                if self
                    .function_place(func_index, stmt_index, address)
                    .is_none()
                {
                    self.record_direct_global(address, unsafe_globals);
                }
            }
            Stmt::Store { address, value, .. } => {
                if self
                    .function_place(func_index, stmt_index, address)
                    .is_none()
                {
                    self.record_direct_global(address, unsafe_globals);
                }
                self.record_function_operand_global(func_index, stmt_index, value, unsafe_globals);
            }
            Stmt::Gep {
                base,
                byte_off: Some(_),
                ..
            } => {
                if self.function_place(func_index, stmt_index, base).is_none() {
                    self.record_direct_global(base, unsafe_globals);
                }
            }
            Stmt::Gep { base, .. } => {
                self.record_function_operand_global(func_index, stmt_index, base, unsafe_globals)
            }
            Stmt::GlobalRef { .. } => {}
            _ => {
                for operand in stmt_operands(stmt) {
                    self.record_function_operand_global(
                        func_index,
                        stmt_index,
                        operand,
                        unsafe_globals,
                    );
                }
            }
        }
    }

    fn record_global_init_unsafe_globals(
        &self,
        stmt_index: usize,
        stmt: &Stmt,
        unsafe_globals: &mut HashSet<String>,
    ) {
        match stmt {
            Stmt::Load { address, .. } => {
                if self.global_init_place(stmt_index, address).is_none() {
                    self.record_direct_global(address, unsafe_globals);
                }
            }
            Stmt::Store { address, value, .. } => {
                if self.global_init_place(stmt_index, address).is_none() {
                    self.record_direct_global(address, unsafe_globals);
                }
                self.record_global_init_operand_global(stmt_index, value, unsafe_globals);
            }
            Stmt::Gep {
                base,
                byte_off: Some(_),
                ..
            } => {
                if self.global_init_place(stmt_index, base).is_none() {
                    self.record_direct_global(base, unsafe_globals);
                }
            }
            Stmt::Gep { base, .. } => {
                self.record_global_init_operand_global(stmt_index, base, unsafe_globals);
            }
            Stmt::GlobalRef { .. } => {}
            _ => {
                for operand in stmt_operands(stmt) {
                    self.record_global_init_operand_global(stmt_index, operand, unsafe_globals);
                }
            }
        }
    }

    fn record_function_operand_global(
        &self,
        func_index: usize,
        stmt_index: usize,
        operand: &str,
        unsafe_globals: &mut HashSet<String>,
    ) {
        if let Some(place) = self.function_place(func_index, stmt_index, operand) {
            unsafe_globals.insert(place.root);
        } else {
            self.record_direct_global(operand, unsafe_globals);
        }
    }

    fn record_global_init_operand_global(
        &self,
        stmt_index: usize,
        operand: &str,
        unsafe_globals: &mut HashSet<String>,
    ) {
        if let Some(place) = self.global_init_place(stmt_index, operand) {
            unsafe_globals.insert(place.root);
        } else {
            self.record_direct_global(operand, unsafe_globals);
        }
    }

    fn record_direct_global(&self, operand: &str, unsafe_globals: &mut HashSet<String>) {
        let global = canonical_symbol(operand);
        if self.globals.contains(global) {
            unsafe_globals.insert(global.to_string());
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
        if let Some(&target_index) = self.functions.get(canonical_symbol(value)) {
            let target = &self.module.functions[target_index];
            out.targets.insert(target.key.clone());
            out.sites.insert(format!(
                "function:{}@{}",
                target.key,
                self.owner_key(func_index)
            ));
            return WalkResult::Simple;
        }
        if self.globals.contains(canonical_symbol(value)) {
            return self.resolve_global(canonical_symbol(value), depth, visiting, out);
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
            | Stmt::VaStart { .. }
            | Stmt::VaEnd { .. }
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
        let Some(&callee_index) = self.functions.get(canonical_symbol(callee)) else {
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
        if self.externally_callable[callee_index] {
            return WalkResult::Complex;
        }
        let call_count = self.preanalysis.direct_call_count[callee_index];
        let actuals = self
            .preanalysis
            .direct_actuals
            .get(&(callee_index, param_index))
            .cloned()
            .unwrap_or_default();
        if call_count == 0 || actuals.len() != call_count {
            return WalkResult::Complex;
        }
        for actual in actuals {
            if self.resolve_value(
                actual.caller_index,
                actual.stmt_index,
                actual.actual,
                depth,
                visiting,
                out,
            ) == WalkResult::Complex
            {
                return WalkResult::Complex;
            }
        }
        WalkResult::Simple
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
        let stores = self
            .preanalysis
            .stores_by_place
            .get(place)
            .cloned()
            .unwrap_or_default();
        if stores.is_empty() {
            return WalkResult::Complex;
        }
        for store in stores {
            match store {
                StoreSite::Function {
                    func_index,
                    stmt_index,
                } => {
                    let Stmt::Store { value, .. } =
                        &self.module.functions[func_index].body[stmt_index]
                    else {
                        unreachable!("store index must reference a store statement");
                    };
                    let value = value.clone();
                    if self.resolve_value(func_index, stmt_index, &value, depth, visiting, out)
                        == WalkResult::Complex
                    {
                        return WalkResult::Complex;
                    }
                }
                StoreSite::GlobalInit { stmt_index } => {
                    let Stmt::Store { value, .. } = &self.module.global_init[stmt_index] else {
                        unreachable!("store index must reference a global initializer store");
                    };
                    let value = value.clone();
                    if self.resolve_global_init_value(stmt_index, &value, depth, visiting, out)
                        == WalkResult::Complex
                    {
                        return WalkResult::Complex;
                    }
                }
            }
        }
        WalkResult::Simple
    }

    fn resolve_global_init_value(
        &mut self,
        before_stmt: usize,
        value: &str,
        depth: usize,
        visiting: &mut HashSet<(usize, String, usize)>,
        out: &mut ValueResolution,
    ) -> WalkResult {
        if let Some(&target_index) = self.functions.get(canonical_symbol(value)) {
            let target = &self.module.functions[target_index];
            out.targets.insert(target.key.clone());
            out.sites
                .insert(format!("function:{}@global_init", target.key));
            return WalkResult::Simple;
        }
        if self.globals.contains(canonical_symbol(value)) {
            return self.resolve_global(canonical_symbol(value), depth + 1, visiting, out);
        }
        let Some(stmt_index) = self.global_init_definition_before(value, before_stmt) else {
            return WalkResult::Complex;
        };
        match &self.module.global_init[stmt_index] {
            Stmt::Assign { sources, .. } => {
                self.resolve_all_global_init_sources(stmt_index, sources, depth, visiting, out)
            }
            Stmt::Gep { base, .. } => {
                self.resolve_global_init_value(stmt_index, base, depth, visiting, out)
            }
            _ => WalkResult::Complex,
        }
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
        let global = canonical_symbol(global);
        !self.externally_writable_globals.contains(global)
            && self.globals.contains(global)
            && !self.preanalysis.unsafe_globals.contains(global)
    }

    fn global_place_is_simple(&self, place: &SubObj) -> bool {
        self.global_is_never_address_taken(&place.root)
    }

    fn function_has_unsafe_escape(&self, target: &str) -> bool {
        let target = canonical_symbol(target);
        if let Some(&unsafe_escape) = self.function_escape_cache.borrow().get(target) {
            return unsafe_escape;
        }
        let unsafe_escape = self.compute_function_has_unsafe_escape(target);
        self.function_escape_cache
            .borrow_mut()
            .insert(target.to_string(), unsafe_escape);
        unsafe_escape
    }

    fn compute_function_has_unsafe_escape(&self, target: &str) -> bool {
        let Some(&target_index) = self.functions.get(target) else {
            return true;
        };
        let mut visiting = HashSet::new();
        self.preanalysis.function_symbol_uses[target_index]
            .iter()
            .any(|site| match *site {
                SymbolUseSite::Function {
                    func_index,
                    stmt_index,
                } => self.function_symbol_use_escapes(
                    func_index,
                    stmt_index,
                    &self.module.functions[func_index].body[stmt_index],
                    target,
                    0,
                    &mut visiting,
                ),
                SymbolUseSite::GlobalInit { stmt_index } => {
                    function_use_is_unsafe(&self.module.global_init[stmt_index], target, |global| {
                        self.global_is_never_address_taken(global)
                    })
                }
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
            Stmt::Assign { dest, sources, .. }
                if sources.iter().any(|source| same_symbol(source, target)) =>
            {
                self.local_value_escapes(func_index, dest, depth, visiting)
            }
            Stmt::ScalarOp { dest, lhs, rhs, .. }
                if same_symbol(lhs, target) || same_symbol(rhs, target) =>
            {
                self.local_value_escapes(func_index, dest, depth, visiting)
            }
            Stmt::Store { address, value, .. } if same_symbol(value, target) => !self
                .function_place(func_index, stmt_index, address)
                .map(|place| self.global_place_is_simple(&place))
                .unwrap_or_else(|| self.global_is_never_address_taken(address)),
            Stmt::CallDirect {
                callee, sig, args, ..
            } => args.iter().enumerate().any(|(index, arg)| {
                same_symbol(arg, target)
                    && self.call_arg_escapes(callee, sig.vararg, index, target, depth, visiting)
            }),
            Stmt::CallIndirect { operand, args, .. } => {
                !same_symbol(operand, target) && args.iter().any(|arg| same_symbol(arg, target))
            }
            Stmt::Return { value, .. }
                if value
                    .as_deref()
                    .is_some_and(|value| same_symbol(value, target)) =>
            {
                self.return_value_escapes(func_index, target, depth, visiting)
            }
            Stmt::Load { address, .. } => same_symbol(address, target),
            Stmt::Gep { base, .. } => same_symbol(base, target),
            Stmt::PtrToInt { source, .. } => same_symbol(source, target),
            Stmt::IntToPtr { source, .. } => same_symbol(source, target),
            Stmt::Memcpy { dst, src, .. } => same_symbol(dst, target) || same_symbol(src, target),
            Stmt::Memset { dst, value, .. } => {
                same_symbol(dst, target) || same_symbol(value, target)
            }
            Stmt::Unknown {
                operands, results, ..
            } => {
                operands.iter().any(|operand| same_symbol(operand, target))
                    || results.iter().any(|result| same_symbol(result, target))
            }
            Stmt::VaStart { list, .. } | Stmt::VaEnd { list, .. } => same_symbol(list, target),
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
        let escapes = self.preanalysis.local_uses[func_index]
            .get(value)
            .is_some_and(|uses| {
                uses.iter().any(|&stmt_index| {
                    self.local_value_use_escapes(
                        func_index,
                        stmt_index,
                        &self.module.functions[func_index].body[stmt_index],
                        value,
                        depth,
                        visiting,
                    )
                })
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
            Stmt::VaStart { list, .. } | Stmt::VaEnd { list, .. } => list == value,
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
        let Some(&callee_index) = self.functions.get(canonical_symbol(callee)) else {
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
        if self.externally_callable[func_index] || func.address_taken {
            return true;
        }
        let consumers = &self.preanalysis.return_consumers[func_index];
        for consumer in consumers {
            if self.local_value_escapes(consumer.caller_index, consumer.dest, depth + 1, visiting) {
                return true;
            }
        }
        consumers.is_empty() && !value.is_empty()
    }

    fn address_taken_sites(&self) -> &BTreeMap<String, BTreeSet<String>> {
        &self.preanalysis.address_taken_sites
    }

    fn function_place(&self, func_index: usize, before_stmt: usize, value: &str) -> Option<SubObj> {
        let symbol = canonical_symbol(value);
        if self.globals.contains(symbol) {
            return Some(SubObj {
                root: symbol.to_string(),
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
        let symbol = canonical_symbol(value);
        if self.globals.contains(symbol) {
            return Some(SubObj {
                root: symbol.to_string(),
                byte_off: 0,
            });
        }
        let stmt_index = self.global_init_definition_before(value, before_stmt)?;
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

    fn param_index(&self, func_index: usize, value: &str) -> Option<usize> {
        self.module.functions[func_index]
            .param_names
            .iter()
            .position(|param| param == value)
    }

    fn global_init_definition_before(&self, value: &str, before_stmt: usize) -> Option<usize> {
        let definitions = self.global_init_definitions.get(value)?;
        let position = definitions.partition_point(|&stmt_index| stmt_index < before_stmt);
        position
            .checked_sub(1)
            .map(|position| definitions[position])
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
        | Stmt::VaStart { .. }
        | Stmt::VaEnd { .. }
        | Stmt::GlobalRef { .. } => None,
    }
}

fn stmt_operands(stmt: &Stmt) -> Vec<&str> {
    match stmt {
        Stmt::Alloca { .. } | Stmt::VarArg { .. } | Stmt::GlobalRef { .. } => Vec::new(),
        Stmt::VaStart { list, .. } | Stmt::VaEnd { list, .. } => vec![list.as_str()],
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
        Stmt::VaStart { list, .. } | Stmt::VaEnd { list, .. } => vec![list.as_str()],
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

fn global_init_function_escape_operands(stmt: &Stmt) -> Vec<&str> {
    match stmt {
        Stmt::Assign { .. } | Stmt::GlobalRef { .. } => Vec::new(),
        Stmt::ScalarOp { dest, lhs, rhs, .. } => {
            vec![dest.as_str(), lhs.as_str(), rhs.as_str()]
        }
        Stmt::Store { value, .. } => vec![value.as_str()],
        Stmt::VaStart { list, .. } | Stmt::VaEnd { list, .. } => vec![list.as_str()],
        Stmt::CallIndirect {
            operand,
            args,
            dest,
            ..
        } => std::iter::once(operand.as_str())
            .chain(args.iter().map(String::as_str))
            .chain(dest.as_deref())
            .collect(),
        Stmt::Load { address, .. } => vec![address.as_str()],
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
        Stmt::CallDirect {
            callee, args, dest, ..
        } => std::iter::once(callee.as_str())
            .chain(args.iter().map(String::as_str))
            .chain(dest.as_deref())
            .collect(),
        Stmt::Alloca { dest, .. } | Stmt::VarArg { dest, .. } => vec![dest.as_str()],
    }
}

fn canonical_symbol(value: &str) -> &str {
    value.strip_prefix('@').unwrap_or(value)
}

fn same_symbol(lhs: &str, rhs: &str) -> bool {
    canonical_symbol(lhs) == canonical_symbol(rhs)
}

fn reachable_functions(
    module: &Pir,
    build_mode: BuildMode,
    externally_callable: &[bool],
) -> Vec<bool> {
    if build_mode == BuildMode::Library {
        return vec![true; module.functions.len()];
    }
    if !module
        .functions
        .iter()
        .enumerate()
        .any(|(index, func)| !func.external && externally_callable[index])
    {
        // Without a closed-world entry point, pruning would turn an absent root declaration into
        // an exactness claim. Preserve the historical fail-closed behavior for such fixtures and
        // partial modules by treating every function as reachable.
        return vec![true; module.functions.len()];
    }

    let functions = module
        .functions
        .iter()
        .enumerate()
        .map(|(index, func)| (canonical_symbol(&func.key), index))
        .collect::<HashMap<_, _>>();
    let mut reachable = module
        .functions
        .iter()
        .enumerate()
        .map(|(index, func)| externally_callable[index] || func.address_taken)
        .collect::<Vec<_>>();
    let mut work = reachable
        .iter()
        .enumerate()
        .filter_map(|(index, &is_reachable)| is_reachable.then_some(index))
        .collect::<Vec<_>>();

    while let Some(func_index) = work.pop() {
        for stmt in &module.functions[func_index].body {
            let Stmt::CallDirect { callee, .. } = stmt else {
                continue;
            };
            let Some(&callee_index) = functions.get(canonical_symbol(callee)) else {
                continue;
            };
            if !reachable[callee_index] {
                reachable[callee_index] = true;
                work.push(callee_index);
            }
        }
    }
    reachable
}

fn function_use_is_unsafe<F>(stmt: &Stmt, target: &str, mut global_is_safe_slot: F) -> bool
where
    F: FnMut(&str) -> bool,
{
    match stmt {
        Stmt::Assign { .. } => false,
        Stmt::ScalarOp { dest, lhs, rhs, .. } => {
            same_symbol(dest, target) || same_symbol(lhs, target) || same_symbol(rhs, target)
        }
        Stmt::Store { address, value, .. } if same_symbol(value, target) => {
            !global_is_safe_slot(address.as_str())
        }
        Stmt::Store { .. } => false,
        // A function address cannot legitimately be a `va_list`; if one appears there, say so.
        Stmt::VaStart { list, .. } | Stmt::VaEnd { list, .. } => same_symbol(list, target),
        Stmt::CallIndirect {
            operand,
            args,
            dest,
            ..
        } => {
            args.iter().any(|arg| same_symbol(arg, target))
                || (!same_symbol(operand, target)
                    && dest
                        .as_deref()
                        .is_some_and(|dest| same_symbol(dest, target)))
        }
        Stmt::Load { address, .. } => same_symbol(address, target),
        Stmt::Gep { base, .. } => same_symbol(base, target),
        Stmt::PtrToInt { source, .. } => same_symbol(source, target),
        Stmt::IntToPtr { source, .. } => same_symbol(source, target),
        Stmt::Memcpy { dst, src, .. } => same_symbol(dst, target) || same_symbol(src, target),
        Stmt::Memset { dst, value, .. } => same_symbol(dst, target) || same_symbol(value, target),
        Stmt::Unknown {
            operands, results, ..
        } => {
            operands.iter().any(|operand| same_symbol(operand, target))
                || results.iter().any(|result| same_symbol(result, target))
        }
        Stmt::Return { value, .. } => value
            .as_deref()
            .is_some_and(|value| same_symbol(value, target)),
        Stmt::CallDirect {
            callee, args, dest, ..
        } => {
            same_symbol(callee, target)
                || dest
                    .as_deref()
                    .is_some_and(|dest| same_symbol(dest, target))
                || args.iter().any(|arg| same_symbol(arg, target))
        }
        Stmt::Alloca { dest, .. } => same_symbol(dest, target),
        Stmt::VarArg { dest, .. } => same_symbol(dest, target),
        Stmt::GlobalRef { .. } => false,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn fixture(name: &str) -> Pir {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/synthetic/m2_2")
            .join(name);
        Pir::from_path(path).unwrap()
    }

    fn resolver(module: &Pir) -> SimpleResolver<'_> {
        SimpleResolver::new(module, 4, BuildMode::Executable, &BTreeSet::new())
    }

    #[test]
    fn preanalysis_indexes_parameter_actuals_symbol_uses_and_local_uses() {
        let module = fixture("simple_param_actual.pir.json");
        let resolver = resolver(&module);
        let invoke = resolver.functions["invoke"];
        let cb = resolver.functions["cb"];

        assert_eq!(resolver.preanalysis.direct_call_count[invoke], 1);
        let actuals = &resolver.preanalysis.direct_actuals[&(invoke, 0)];
        assert_eq!(actuals.len(), 1);
        assert_eq!(actuals[0].actual, "cb");
        assert_eq!(resolver.preanalysis.local_uses[invoke]["fp"], [0]);
        assert!(matches!(
            resolver.preanalysis.function_symbol_uses[cb].as_slice(),
            [SymbolUseSite::Function {
                func_index: 0,
                stmt_index: 0
            }]
        ));
    }

    #[test]
    fn preanalysis_indexes_subobject_stores_and_return_consumers() {
        let fields = fixture("simple_global_fields.pir.json");
        let fields_resolver = resolver(&fields);
        assert_eq!(
            fields_resolver.preanalysis.stores_by_place[&SubObj {
                root: "Table".into(),
                byte_off: 0,
            }]
                .len(),
            1
        );
        assert_eq!(
            fields_resolver.preanalysis.stores_by_place[&SubObj {
                root: "Table".into(),
                byte_off: 8,
            }]
                .len(),
            1
        );

        let mut initializer = fixture("simple_global_fields.pir.json");
        initializer.functions[0].body.clear();
        initializer.global_init = vec![
            Stmt::Assign {
                dest: "%slot".into(),
                sources: vec!["@Table".into()],
                loc: None,
            },
            Stmt::Store {
                address: "%slot".into(),
                value: "cb".into(),
                volatile: false,
                access_bytes: None,
                loc: None,
            },
            Stmt::Assign {
                dest: "%slot".into(),
                sources: vec!["@Table".into()],
                loc: None,
            },
        ];
        let initializer_resolver = resolver(&initializer);
        assert_eq!(
            initializer_resolver.global_init_definitions["%slot"],
            [0, 2]
        );
        assert!(matches!(
            initializer_resolver.preanalysis.stores_by_place[&SubObj {
                root: "Table".into(),
                byte_off: 0,
            }]
                .as_slice(),
            [StoreSite::GlobalInit { stmt_index: 1 }]
        ));

        let returns = fixture("simple_return_value.pir.json");
        let returns_resolver = resolver(&returns);
        let choose = returns_resolver.functions["choose"];
        let consumers = &returns_resolver.preanalysis.return_consumers[choose];
        assert_eq!(consumers.len(), 1);
        assert_eq!(consumers[0].caller_index, 0);
        assert_eq!(consumers[0].dest, "%fp");
    }
}
