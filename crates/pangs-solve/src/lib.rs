use std::collections::{BTreeMap, BTreeSet, VecDeque};

use pangs_pag::{BuildMode, CallKind, NodeId, NodeKind, OmegaSeedKind, Pag, SeedTarget};
use pangs_pir::{fsa_compatible, Pir, Signature};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SolveMetrics {
    pub partition_count: usize,
    pub partition_p50_size: usize,
    pub partition_p95_size: usize,
    pub partition_max_size: usize,
    pub oversize_fallbacks: usize,
    pub rounds: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SolveResult {
    #[serde(default)]
    pub indirect_calls: Vec<IndirectCallResolution>,
    #[serde(default)]
    pub unknown_callers: BTreeSet<String>,
    #[serde(default)]
    pub globals: BTreeMap<String, GlobalResolution>,
    #[serde(default)]
    pub nodes: BTreeMap<String, NodeResolution>,
    #[serde(default)]
    pub metrics: SolveMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndirectCallResolution {
    pub callsite_key: String,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub unknown_callee: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlobalResolution {
    pub escape_external: bool,
    pub never_written: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeResolution {
    pub reaches_function_pointer: bool,
    #[serde(default)]
    pub external: bool,
    #[serde(default)]
    pub pointee_globals: Vec<String>,
}

pub fn solve_steensgaard(pir: &Pir, pag: &Pag, build_mode: BuildMode) -> SolveResult {
    Solver::new(pir, pag, build_mode).solve()
}

#[derive(Debug, Clone)]
struct FunctionMeta {
    sig: Signature,
    address_taken: bool,
    external: bool,
    param_nodes: Vec<NodeId>,
    ret_node: Option<NodeId>,
}

#[derive(Debug, Clone, Default)]
struct ClassData {
    parent: usize,
    size: usize,
    node_count: usize,
    pointee: Option<usize>,
    ext: bool,
    esc: bool,
    icall_sites: BTreeSet<usize>,
    fn_objs: BTreeSet<String>,
    global_objs: BTreeSet<String>,
}

struct Solver<'a> {
    pir: &'a Pir,
    pag: &'a Pag,
    build_mode: BuildMode,
    classes: Vec<ClassData>,
    function_meta: BTreeMap<String, FunctionMeta>,
    function_object_nodes: BTreeMap<String, NodeId>,
    global_object_nodes: BTreeMap<String, NodeId>,
    callsites_by_index: Vec<&'a pangs_pag::Callsite>,
    worklist: VecDeque<usize>,
    seen_pairs: BTreeSet<(usize, String)>,
    external_applied: BTreeSet<usize>,
    escaped_fn_applied: BTreeSet<String>,
}

impl<'a> Solver<'a> {
    fn new(pir: &'a Pir, pag: &'a Pag, build_mode: BuildMode) -> Self {
        let mut function_meta: BTreeMap<String, FunctionMeta> = pir
            .functions
            .iter()
            .map(|func| {
                (
                    func.key.clone(),
                    FunctionMeta {
                        sig: func.sig.clone(),
                        address_taken: func.address_taken,
                        external: func.external,
                        param_nodes: Vec::new(),
                        ret_node: None,
                    },
                )
            })
            .collect();
        let mut function_object_nodes = BTreeMap::new();
        let mut global_object_nodes = BTreeMap::new();

        let mut classes = Vec::with_capacity(pag.nodes.len());
        for (index, node) in pag.nodes.iter().enumerate() {
            let mut data = ClassData {
                parent: index,
                size: 1,
                node_count: 1,
                ..ClassData::default()
            };
            match &node.kind {
                NodeKind::Object { object, key, .. } => match object {
                    pangs_pag::ObjectKind::Function => {
                        data.fn_objs.insert(key.clone());
                        function_object_nodes.insert(key.clone(), node.id);
                    }
                    pangs_pag::ObjectKind::Global => {
                        data.global_objs.insert(key.clone());
                        global_object_nodes.insert(key.clone(), node.id);
                    }
                    pangs_pag::ObjectKind::Alloca => {}
                },
                NodeKind::Param { func, index } => {
                    if let Some(meta) = function_meta.get_mut(func) {
                        if meta.param_nodes.len() <= *index as usize {
                            meta.param_nodes
                                .resize(*index as usize + 1, NodeId(u32::MAX));
                        }
                        meta.param_nodes[*index as usize] = node.id;
                    }
                }
                NodeKind::Return { func } => {
                    if let Some(meta) = function_meta.get_mut(func) {
                        meta.ret_node = Some(node.id);
                    }
                }
                NodeKind::Value { .. } => {}
            }
            classes.push(data);
        }

        let callsites_by_index = pag.callsites.iter().collect();

        Self {
            pir,
            pag,
            build_mode,
            classes,
            function_meta,
            function_object_nodes,
            global_object_nodes,
            callsites_by_index,
            worklist: VecDeque::new(),
            seen_pairs: BTreeSet::new(),
            external_applied: BTreeSet::new(),
            escaped_fn_applied: BTreeSet::new(),
        }
    }

    fn solve(mut self) -> SolveResult {
        self.apply_edge_rules();
        self.register_indirect_calls();
        self.apply_seeds();
        self.seed_main_entry_params();

        while let Some(class) = self.worklist.pop_front() {
            let root = self.find(class);
            self.process_class(root);
        }

        self.finish()
    }

    fn apply_edge_rules(&mut self) {
        for edge in &self.pag.edges {
            match edge.kind {
                pangs_pag::EdgeKind::AddrOf => {
                    let ptr = self.class_of(edge.dst);
                    let obj = self.class_of(edge.src);
                    let pointee = self.pointee_of(ptr);
                    self.join(pointee, obj);
                }
                pangs_pag::EdgeKind::Assign => {
                    let src = self.class_of(edge.src);
                    let dst = self.class_of(edge.dst);
                    self.join(src, dst);
                }
                pangs_pag::EdgeKind::Load => {
                    let dst = self.class_of(edge.dst);
                    let src = self.class_of(edge.src);
                    let pointee = self.pointee_of(src);
                    self.join(dst, pointee);
                }
                pangs_pag::EdgeKind::Store => {
                    let src = self.class_of(edge.src);
                    let dst = self.class_of(edge.dst);
                    let pointee = self.pointee_of(dst);
                    self.join(pointee, src);
                }
                pangs_pag::EdgeKind::Gep { .. } => {
                    let dst = self.class_of(edge.dst);
                    let src = self.class_of(edge.src);
                    let dst_p = self.pointee_of(dst);
                    let src_p = self.pointee_of(src);
                    self.join(dst_p, src_p);
                }
                pangs_pag::EdgeKind::Memcpy { .. } => {
                    let dst = self.class_of(edge.dst);
                    let src = self.class_of(edge.src);
                    let dst_p = self.pointee_of(dst);
                    let src_p = self.pointee_of(src);
                    let dst_pp = self.pointee_of(dst_p);
                    let src_pp = self.pointee_of(src_p);
                    self.join(dst_pp, src_pp);
                }
            }
        }
    }

    fn register_indirect_calls(&mut self) {
        for (site_index, callsite) in self.pag.callsites.iter().enumerate() {
            if callsite.kind != CallKind::Indirect {
                continue;
            }
            let Some(operand) = callsite.operand else {
                continue;
            };
            let operand = self.class_of(operand);
            let cls = self.pointee_of(operand);
            let root = self.find(cls);
            self.classes[root].icall_sites.insert(site_index);
            self.enqueue(root);
        }
    }

    fn apply_seeds(&mut self) {
        for seed in &self.pag.omega_seeds {
            match (seed.kind, seed.target) {
                (OmegaSeedKind::ExportedSymbol, SeedTarget::Node(id))
                | (OmegaSeedKind::ImportedSymbol, SeedTarget::Node(id)) => {
                    let class = self.class_of(id);
                    self.set_esc(class);
                }
                (OmegaSeedKind::PtrToInt, SeedTarget::Node(id))
                | (OmegaSeedKind::UnknownOperandEscape, SeedTarget::Node(id)) => {
                    let class = self.class_of(id);
                    let pointee = self.pointee_of(class);
                    self.set_esc(pointee);
                }
                (OmegaSeedKind::IntToPtr, SeedTarget::Node(id))
                | (OmegaSeedKind::UnknownResultExternal, SeedTarget::Node(id)) => {
                    let class = self.class_of(id);
                    self.set_ext(class);
                }
                (OmegaSeedKind::ExternalCallBoundary, SeedTarget::Callsite(id)) => {
                    self.apply_external_call(id.0 as usize);
                }
                (OmegaSeedKind::VarargCallBoundary, SeedTarget::Callsite(id)) => {
                    self.apply_vararg_call(id.0 as usize);
                }
                _ => {}
            }
        }
    }

    fn seed_main_entry_params(&mut self) {
        if self.build_mode != BuildMode::Executable {
            return;
        }
        let Some(main) = self.function_meta.get("main").cloned() else {
            return;
        };
        for param in main.param_nodes.iter().skip(1).copied() {
            if param.0 != u32::MAX {
                let class = self.class_of(param);
                self.set_ext(class);
            }
        }
    }

    fn finish(mut self) -> SolveResult {
        let mut indirect_calls = Vec::new();
        for callsite in &self.pag.callsites {
            if callsite.kind != CallKind::Indirect {
                continue;
            }
            let Some(operand) = callsite.operand else {
                continue;
            };
            let operand = self.class_of(operand);
            let pointee = self.pointee_of(operand);
            let root = self.find(pointee);
            let mut targets = self.classes[root]
                .fn_objs
                .iter()
                .filter_map(|key| {
                    let meta = self.function_meta.get(key)?;
                    if !meta.address_taken {
                        return None;
                    }
                    if !fsa_compatible(&callsite.sig, &meta.sig) {
                        return None;
                    }
                    Some(key.clone())
                })
                .collect::<Vec<_>>();
            targets.sort();
            indirect_calls.push(IndirectCallResolution {
                callsite_key: callsite.key.clone(),
                targets,
                unknown_callee: self.classes[root].ext,
            });
        }

        let mut unknown_callers = BTreeSet::new();
        let function_keys = self.function_meta.keys().cloned().collect::<Vec<_>>();
        for key in function_keys {
            let Some(class) = self.function_object_class(&key) else {
                continue;
            };
            let root = self.find(class);
            if self.classes[root].esc {
                unknown_callers.insert(key);
            }
        }

        let mut stored_classes = BTreeSet::new();
        for edge in &self.pag.edges {
            if !matches!(edge.kind, pangs_pag::EdgeKind::Store) {
                continue;
            }
            let dst = self.class_of(edge.dst);
            let pointee = self.pointee_of(dst);
            stored_classes.insert(self.find(pointee));
        }

        let mut globals = BTreeMap::new();
        for global in &self.pir.globals {
            let Some(class) = self.global_object_class(&global.key) else {
                continue;
            };
            let root = self.find(class);
            let escape_external = self.classes[root].esc;
            let never_written = !escape_external && !stored_classes.contains(&root);
            globals.insert(
                global.key.clone(),
                GlobalResolution {
                    escape_external,
                    never_written,
                },
            );
        }

        let mut nodes = BTreeMap::new();
        for node in &self.pag.nodes {
            if !matches!(
                node.kind,
                NodeKind::Value { .. } | NodeKind::Param { .. } | NodeKind::Return { .. }
            ) {
                continue;
            }
            let root = self.class_of(node.id);
            let external = self.classes[root].ext;
            let pointee_globals = self.classes[root]
                .pointee
                .map(|p| {
                    let pointee = self.find(p);
                    let mut globals = self.classes[pointee]
                        .global_objs
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>();
                    globals.sort();
                    globals
                })
                .unwrap_or_default();
            let reaches_function_pointer = self.classes[root]
                .pointee
                .map(|p| {
                    let pointee = self.find(p);
                    !self.classes[pointee].fn_objs.is_empty()
                        || self.classes[pointee].ext
                        || !self.classes[pointee].icall_sites.is_empty()
                })
                .unwrap_or(false);
            nodes.insert(
                node.label.clone(),
                NodeResolution {
                    reaches_function_pointer,
                    external,
                    pointee_globals,
                },
            );
        }

        let mut sizes = Vec::new();
        for index in 0..self.classes.len() {
            let root = self.find(index);
            if root == index && self.classes[index].node_count > 0 {
                sizes.push(self.classes[index].node_count);
            }
        }
        sizes.sort_unstable();
        let metrics = SolveMetrics {
            partition_count: sizes.len(),
            partition_p50_size: percentile(&sizes, 50),
            partition_p95_size: percentile(&sizes, 95),
            partition_max_size: sizes.last().copied().unwrap_or(0),
            oversize_fallbacks: 0,
            rounds: 1,
        };

        SolveResult {
            indirect_calls,
            unknown_callers,
            globals,
            nodes,
            metrics,
        }
    }

    fn process_class(&mut self, class: usize) {
        let root = self.find(class);
        let ext = self.classes[root].ext;
        let esc = self.classes[root].esc;

        if ext || esc {
            if let Some(pointee) = self.classes[root].pointee {
                self.set_ext(pointee);
                self.set_esc(pointee);
            }
        }

        if esc {
            let escaped = self.classes[root]
                .fn_objs
                .iter()
                .cloned()
                .collect::<Vec<_>>();
            for func in escaped {
                if !self.escaped_fn_applied.insert(func.clone()) {
                    continue;
                }
                if let Some(meta) = self.function_meta.get(&func).cloned() {
                    for param in meta.param_nodes {
                        if param.0 != u32::MAX {
                            let class = self.class_of(param);
                            self.set_ext(class);
                        }
                    }
                    if let Some(ret) = meta.ret_node {
                        let class = self.class_of(ret);
                        let pointee = self.pointee_of(class);
                        self.set_esc(pointee);
                    }
                }
            }
        }

        let site_ids = self.classes[root]
            .icall_sites
            .iter()
            .copied()
            .collect::<Vec<_>>();
        let funcs = self.classes[root]
            .fn_objs
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        for site_index in site_ids {
            if ext {
                self.apply_external_call(site_index);
            }
            for func in &funcs {
                if !self.seen_pairs.insert((site_index, func.clone())) {
                    continue;
                }
                let callsite = self.callsites_by_index[site_index];
                let Some(meta) = self.function_meta.get(func).cloned() else {
                    continue;
                };
                if !fsa_compatible(&callsite.sig, &meta.sig) {
                    continue;
                }
                self.bind_indirect_call(site_index, func, &meta);
            }
        }
    }

    fn bind_indirect_call(&mut self, site_index: usize, func: &str, meta: &FunctionMeta) {
        let callsite = self.callsites_by_index[site_index];
        if meta.external {
            self.apply_external_call(site_index);
        }
        for (arg, param) in callsite.args.iter().zip(meta.param_nodes.iter()) {
            if param.0 == u32::MAX {
                continue;
            }
            let arg = self.class_of(*arg);
            let param = self.class_of(*param);
            self.join(arg, param);
        }
        if let (Some(result), Some(ret)) = (callsite.result, meta.ret_node) {
            let result = self.class_of(result);
            let ret = self.class_of(ret);
            self.join(result, ret);
        }
        let _ = func;
    }

    fn apply_external_call(&mut self, site_index: usize) {
        if !self.external_applied.insert(site_index) {
            return;
        }
        let callsite = self.callsites_by_index[site_index];
        for arg in &callsite.args {
            let arg = self.class_of(*arg);
            let pointee = self.pointee_of(arg);
            self.set_esc(pointee);
        }
        if let Some(result) = callsite.result {
            let result = self.class_of(result);
            self.set_ext(result);
        }
    }

    fn apply_vararg_call(&mut self, site_index: usize) {
        let callsite = self.callsites_by_index[site_index];
        let fixed = callsite.sig.params.len();
        let extra_args = callsite
            .args
            .iter()
            .skip(fixed)
            .copied()
            .collect::<Vec<_>>();
        for arg in extra_args {
            let class = self.class_of(arg);
            let root = self.find(class);
            let Some(pointee) = self.classes[root].pointee else {
                continue;
            };
            self.set_esc(pointee);
        }
    }

    fn function_object_class(&mut self, key: &str) -> Option<usize> {
        let id = *self.function_object_nodes.get(key)?;
        Some(self.class_of(id))
    }

    fn global_object_class(&mut self, key: &str) -> Option<usize> {
        let id = *self.global_object_nodes.get(key)?;
        Some(self.class_of(id))
    }

    fn class_of(&mut self, node: NodeId) -> usize {
        self.find(node.0 as usize)
    }

    fn pointee_of(&mut self, class: usize) -> usize {
        let root = self.find(class);
        if let Some(pointee) = self.classes[root].pointee {
            return self.find(pointee);
        }
        let id = self.classes.len();
        self.classes.push(ClassData {
            parent: id,
            size: 1,
            ..ClassData::default()
        });
        self.classes[root].pointee = Some(id);
        self.enqueue(root);
        id
    }

    fn set_ext(&mut self, class: usize) {
        let root = self.find(class);
        if !self.classes[root].ext {
            self.classes[root].ext = true;
            self.enqueue(root);
        }
    }

    fn set_esc(&mut self, class: usize) {
        let root = self.find(class);
        if !self.classes[root].esc {
            self.classes[root].esc = true;
            self.enqueue(root);
        }
    }

    fn join(&mut self, left: usize, right: usize) -> usize {
        let mut a = self.find(left);
        let mut b = self.find(right);
        if a == b {
            return a;
        }
        if self.classes[a].size < self.classes[b].size {
            std::mem::swap(&mut a, &mut b);
        }

        self.classes[b].parent = a;
        self.classes[a].size += self.classes[b].size;
        self.classes[a].node_count += self.classes[b].node_count;
        self.classes[a].ext |= self.classes[b].ext;
        self.classes[a].esc |= self.classes[b].esc;

        let other_sites = std::mem::take(&mut self.classes[b].icall_sites);
        self.classes[a].icall_sites.extend(other_sites);
        let other_fns = std::mem::take(&mut self.classes[b].fn_objs);
        self.classes[a].fn_objs.extend(other_fns);
        let other_globals = std::mem::take(&mut self.classes[b].global_objs);
        self.classes[a].global_objs.extend(other_globals);

        let pointee = match (self.classes[a].pointee, self.classes[b].pointee) {
            (Some(pa), Some(pb)) => Some(self.join(pa, pb)),
            (Some(pa), None) => Some(self.find(pa)),
            (None, Some(pb)) => Some(self.find(pb)),
            (None, None) => None,
        };
        self.classes[a].pointee = pointee;
        self.classes[b].pointee = None;
        self.enqueue(a);
        a
    }

    fn enqueue(&mut self, class: usize) {
        self.worklist.push_back(class);
    }

    fn find(&mut self, class: usize) -> usize {
        let parent = self.classes[class].parent;
        if parent == class {
            return class;
        }
        let root = self.find(parent);
        self.classes[class].parent = root;
        root
    }
}

fn percentile(sorted: &[usize], pct: usize) -> usize {
    if sorted.is_empty() {
        return 0;
    }
    let index = ((sorted.len() - 1) * pct) / 100;
    sorted[index]
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use pangs_pag::{Pag, PagOpts};

    use super::*;

    fn fixture(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/synthetic/m1_4")
            .join(name)
    }

    fn fixture_m1_5(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/synthetic/m1_5")
            .join(name)
    }

    #[test]
    fn steens_narrows_indirect_targets_and_tracks_escape() {
        let pir = Pir::from_path(fixture("steens_escape_icall.pir.json")).unwrap();
        let pag = Pag::from_pir(
            &pir,
            &PagOpts {
                build_mode: BuildMode::Library,
                ..PagOpts::default()
            },
        );

        let result = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert_eq!(result.indirect_calls.len(), 1);
        assert_eq!(result.indirect_calls[0].callsite_key, "setup@!noloc#0");
        assert_eq!(result.indirect_calls[0].targets, vec!["cb".to_string()]);
        assert!(result.indirect_calls[0].unknown_callee);
        assert!(result.unknown_callers.contains("cb"));
        assert!(!result.unknown_callers.contains("other"));
        assert!(result.globals["@CB"].escape_external);
        assert!(!result.globals["@CB"].never_written);
        assert!(!result.globals["@Local"].escape_external);
        assert!(result.globals["@Local"].never_written);
        assert!(result.metrics.partition_count > 0);
    }

    #[test]
    fn ptrtoint_marks_the_pointee_class_escaped() {
        let pir = Pir::from_path(fixture("ptrtoint_escape.pir.json")).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());

        let result = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert!(result.indirect_calls.is_empty());
        assert!(result.unknown_callers.is_empty());
        assert!(result.globals["@G"].escape_external);
        assert!(!result.globals["@G"].never_written);
    }

    #[test]
    fn inttoptr_keeps_only_unknown_indirect_call_targets() {
        let pir = Pir::from_path(fixture("inttoptr_unknown_call.pir.json")).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());

        let result = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert_eq!(result.indirect_calls.len(), 1);
        assert_eq!(result.indirect_calls[0].callsite_key, "driver@!noloc#0");
        assert!(result.indirect_calls[0].targets.is_empty());
        assert!(result.indirect_calls[0].unknown_callee);
        assert!(!result.unknown_callers.contains("cb"));
        assert!(!result.globals["@G"].escape_external);
        assert!(result.globals["@G"].never_written);
    }

    #[test]
    fn external_call_marks_pointer_argument_targets_escaped() {
        let pir = Pir::from_path(fixture("external_call_arg_escape.pir.json")).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());

        let result = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert!(result.indirect_calls.is_empty());
        assert!(result.unknown_callers.contains("ext_decl"));
        assert!(result.globals["@Esc"].escape_external);
        assert!(!result.globals["@Esc"].never_written);
        assert!(!result.globals["@Local"].escape_external);
        assert!(result.globals["@Local"].never_written);
    }

    #[test]
    fn unknown_operand_and_result_seed_escape_and_unknown_call() {
        let pir = Pir::from_path(fixture("unknown_op_escape.pir.json")).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());

        let result = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert_eq!(result.indirect_calls.len(), 1);
        assert_eq!(result.indirect_calls[0].callsite_key, "driver@!noloc#0");
        assert!(result.indirect_calls[0].targets.is_empty());
        assert!(result.indirect_calls[0].unknown_callee);
        assert!(result.globals["@Esc"].escape_external);
        assert!(!result.globals["@Esc"].never_written);
        assert!(!result.globals["@Local"].escape_external);
        assert!(result.globals["@Local"].never_written);
    }

    #[test]
    fn escaped_function_return_marks_return_pointee_escaped() {
        let pir = Pir::from_path(fixture("escaped_fn_return_escape.pir.json")).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());

        let result = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert!(result.unknown_callers.contains("cb"));
        assert!(result.globals["@CB"].escape_external);
        assert!(!result.globals["@CB"].never_written);
        assert!(result.globals["@Ret"].escape_external);
        assert!(!result.globals["@Ret"].never_written);
        assert!(!result.globals["@Local"].escape_external);
        assert!(result.globals["@Local"].never_written);
    }

    #[test]
    fn store_through_unknown_pointer_escapes_stored_targets() {
        let pir = Pir::from_path(fixture("store_through_unknown_escape.pir.json")).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());

        let result = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert!(result.indirect_calls.is_empty());
        assert!(result.unknown_callers.is_empty());
        assert!(result.globals["@Esc"].escape_external);
        assert!(!result.globals["@Esc"].never_written);
        assert!(!result.globals["@Local"].escape_external);
        assert!(result.globals["@Local"].never_written);
    }

    #[test]
    fn escaped_function_parameter_binding_marks_param_value_unknown_origin() {
        let pir = Pir::from_path(fixture("escaped_fn_param_escape.pir.json")).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());

        let result = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert!(result.unknown_callers.contains("cb"));
        assert!(result.globals["@CB"].escape_external);
        assert!(!result.globals["@CB"].never_written);
        assert!(result.globals["@Esc"].escape_external);
        assert!(!result.globals["@Esc"].never_written);
        assert!(!result.globals["@Local"].escape_external);
        assert!(result.globals["@Local"].never_written);
    }

    #[test]
    fn vararg_boundary_escapes_function_pointer_actuals() {
        let pir = Pir::from_path(fixture_m1_5("vararg_fnptr_flow.pir.json")).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());

        let result = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert!(result.unknown_callers.contains("cb"));
    }
}
