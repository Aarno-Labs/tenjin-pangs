//! Partition-scoped, field-sensitive inclusion (Andersen) solver — the lite design's one
//! real solver (`DESIGN_lite.md` §2 D', `PLAN-M1_lite_delta.md` §M1.4b).
//!
//! It runs *on top of* Steensgaard: `solve_steensgaard_with_classes` provides the union-find
//! classes (Kahlon partitions) and the authoritative Ω/escape facts. Andersen then refines
//! the **points-to sets only** within interesting, within-budget partitions, which sharpens
//! two outputs — indirect-call concrete targets and per-node `pointee_globals` (mod/ref) —
//! while every escape/unknown-caller verdict stays exactly as Steensgaard computed it.
//!
//! Soundness rests on three facts:
//! * Steensgaard unification is a sound over-approximation of Andersen, so refined targets
//!   are always ⊆ the Steensgaard targets (the narrowing ledger, asserted in tests).
//! * Constraints never cross a partition: assign/load/store/gep all *join* in Steensgaard,
//!   and an `&o` object lives in the pointer's pointee class, which we fold into the same
//!   Andersen partition — so a partition is a self-contained subproblem.
//! * Anything reachable only through Ω stays Ω (absorbing), and the escape/unknown outputs
//!   that drive component freezing are taken verbatim from Steensgaard.

use std::collections::{HashMap, HashSet};

use pangs_pag::{CallKind, EdgeKind, NodeId, NodeKind, ObjectKind, Pag};
use pangs_pir::{fsa_compatible, Pir};

use crate::{IndirectCallResolution, SolveResult, SteensClasses};

/// Hard cap on CG-refinement rounds. The loop converges by monotone shrinkage in 2–3
/// rounds in practice; this only guards against a pathological input.
const MAX_ROUNDS: usize = 8;

/// Solve Andersen as a refinement of Steensgaard and fold the refined facts back into a
/// `SolveResult` that is otherwise identical to the Steensgaard answer.
pub fn solve_andersen(
    pir: &Pir,
    pag: &Pag,
    build_mode: pangs_pag::BuildMode,
    partition_budget: u64,
) -> SolveResult {
    let (mut base, classes) = crate::solve_steensgaard_with_classes(pir, pag, build_mode);
    let refined = Refiner::new(pir, pag, &classes, &base, partition_budget).run();

    // Override only the refined facts; keep escape/unknown/globals from Steensgaard.
    base.indirect_calls = refined.indirect_calls;
    for (label, globals) in refined.pointee_globals {
        if let Some(node) = base.nodes.get_mut(&label) {
            node.pointee_globals = globals;
        }
    }
    base.metrics.rounds = refined.rounds;
    base.metrics.oversize_fallbacks = refined.oversize_fallbacks;
    base
}

struct RefinerOutput {
    indirect_calls: Vec<IndirectCallResolution>,
    pointee_globals: Vec<(String, Vec<String>)>,
    rounds: usize,
    oversize_fallbacks: usize,
}

/// One abstract object that can appear in a points-to set: a PAG object node, a lazily
/// materialized field of one, or the single Ω object.
type Cell = u32;

struct Refiner<'a> {
    pir: &'a Pir,
    pag: &'a Pag,
    classes: &'a SteensClasses,
    base: &'a SolveResult,
    budget: u64,

    n_base: usize,
    omega: Cell,

    // PIR/PAG cross-reference tables.
    func_index: HashMap<String, usize>,
    /// PAG object node id for each address-taken function (membership target of `&f`).
    fn_cell_to_index: HashMap<Cell, usize>,
    /// PAG object/field cell -> owning global index (a field of a global still touches it).
    global_of_cell: HashMap<Cell, usize>,
    /// (func_index, param ordinal) -> PAG param node id.
    param_nodes: HashMap<(usize, usize), NodeId>,
    /// func_index -> PAG return node id.
    ret_nodes: HashMap<usize, NodeId>,

    /// Andersen partition root for each Steensgaard class root (class ∪ pointee folded).
    ap_parent: Vec<usize>,
    /// Whether a base node sits in an interesting, within-budget partition.
    in_scope: Vec<bool>,
    oversize_fallbacks: usize,
}

impl<'a> Refiner<'a> {
    fn new(
        pir: &'a Pir,
        pag: &'a Pag,
        classes: &'a SteensClasses,
        base: &'a SolveResult,
        budget: u64,
    ) -> Self {
        let n_base = pag.nodes.len();
        let omega = n_base as Cell;

        let func_index: HashMap<String, usize> = pir
            .functions
            .iter()
            .enumerate()
            .map(|(idx, f)| (f.key.clone(), idx))
            .collect();
        let global_index: HashMap<String, usize> = pir
            .globals
            .iter()
            .enumerate()
            .map(|(idx, g)| (g.key.clone(), idx))
            .collect();

        let mut fn_cell_to_index = HashMap::new();
        let mut global_of_cell = HashMap::new();
        let mut param_nodes = HashMap::new();
        let mut ret_nodes = HashMap::new();
        for node in &pag.nodes {
            match &node.kind {
                NodeKind::Object {
                    object: ObjectKind::Function,
                    key,
                    ..
                } => {
                    if let Some(&idx) = func_index.get(key) {
                        fn_cell_to_index.insert(node.id.0, idx);
                    }
                }
                NodeKind::Object {
                    object: ObjectKind::Global,
                    key,
                    ..
                } => {
                    if let Some(&idx) = global_index.get(key) {
                        global_of_cell.insert(node.id.0, idx);
                    }
                }
                NodeKind::Param { func, index } => {
                    if let Some(&idx) = func_index.get(func) {
                        param_nodes.insert((idx, *index as usize), node.id);
                    }
                }
                NodeKind::Return { func } => {
                    if let Some(&idx) = func_index.get(func) {
                        ret_nodes.insert(idx, node.id);
                    }
                }
                _ => {}
            }
        }

        let mut refiner = Self {
            pir,
            pag,
            classes,
            base,
            budget,
            n_base,
            omega,
            func_index,
            fn_cell_to_index,
            global_of_cell,
            param_nodes,
            ret_nodes,
            ap_parent: Vec::new(),
            in_scope: vec![false; n_base],
            oversize_fallbacks: 0,
        };
        refiner.build_scope();
        refiner
    }

    // ----- partition extraction + interesting-set + oversize guard ----------------------

    fn ap_find(&mut self, mut x: usize) -> usize {
        while self.ap_parent[x] != x {
            self.ap_parent[x] = self.ap_parent[self.ap_parent[x]];
            x = self.ap_parent[x];
        }
        x
    }

    fn ap_union(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.ap_find(a), self.ap_find(b));
        if ra != rb {
            self.ap_parent[rb] = ra;
        }
    }

    /// Fold Steensgaard classes into Andersen partitions (class ∪ pointee), pick the
    /// interesting ones (reachable from icall operands, globals, or escape), then drop any
    /// that blow the oversize budget back to the Steensgaard answer.
    fn build_scope(&mut self) {
        let total = self.classes.pointee.len();
        self.ap_parent = (0..total).collect();
        for root in 0..total {
            if let Some(p) = self.classes.pointee[root] {
                self.ap_union(root, p);
            }
        }

        // Seed interesting Andersen partitions.
        let mut interesting: HashSet<usize> = HashSet::new();
        for callsite in &self.pag.callsites {
            if callsite.kind == CallKind::Indirect {
                if let Some(op) = callsite.operand {
                    let ap = self.ap_find(self.classes.class_of(op));
                    interesting.insert(ap);
                }
            }
        }
        for node in &self.pag.nodes {
            let class = self.classes.class_of(node.id);
            let ap = self.ap_find(class);
            let escape = self.classes.ext[class] || self.classes.esc[class];
            let is_global = matches!(
                node.kind,
                NodeKind::Object {
                    object: ObjectKind::Global,
                    ..
                }
            );
            if escape || is_global {
                interesting.insert(ap);
            }
        }

        // Per-partition oversize estimate: nodes × (nodes + edges touching the partition),
        // a proxy for "constraints × pts bits" (`PLAN-M1_lite_delta.md` §M1.4b).
        let mut nodes_in: HashMap<usize, u64> = HashMap::new();
        for node in &self.pag.nodes {
            let ap = self.ap_find(self.classes.class_of(node.id));
            *nodes_in.entry(ap).or_insert(0) += 1;
        }
        let mut edges_in: HashMap<usize, u64> = HashMap::new();
        for edge in &self.pag.edges {
            let ap = self.ap_find(self.classes.class_of(edge.dst));
            *edges_in.entry(ap).or_insert(0) += 1;
        }

        let mut oversize: HashSet<usize> = HashSet::new();
        for &ap in &interesting {
            let n = nodes_in.get(&ap).copied().unwrap_or(0);
            let e = edges_in.get(&ap).copied().unwrap_or(0);
            let cost = n.saturating_mul(n.saturating_add(e));
            if cost > self.budget {
                oversize.insert(ap);
            }
        }
        self.oversize_fallbacks = oversize.len();

        for i in 0..self.n_base {
            let ap = self.ap_find(self.classes.class_of(NodeId(i as u32)));
            self.in_scope[i] = interesting.contains(&ap) && !oversize.contains(&ap);
        }
    }

    // ----- CG-refinement outer loop -----------------------------------------------------

    fn run(mut self) -> RefinerOutput {
        // Indirect callsites we will refine (in-scope), with their PAG indices.
        let in_scope_sites: Vec<usize> = (0..self.pag.callsites.len())
            .filter(|&i| {
                let cs = &self.pag.callsites[i];
                cs.kind == CallKind::Indirect
                    && cs
                        .operand
                        .map(|op| self.in_scope[op.0 as usize])
                        .unwrap_or(false)
            })
            .collect();

        // Round-0 seed: FSA ∩ Steensgaard targets for the in-scope sites. (The empty
        // `exact_overrides` seam of `PLAN-M1_lite_delta.md` §M1.4b would be subtracted here.)
        let steens_by_key: HashMap<&str, &IndirectCallResolution> = self
            .base
            .indirect_calls
            .iter()
            .map(|r| (r.callsite_key.as_str(), r))
            .collect();
        let mut target_map: HashMap<usize, Vec<usize>> = HashMap::new();
        for &site in &in_scope_sites {
            let key = self.pag.callsites[site].key.as_str();
            let funcs = steens_by_key
                .get(key)
                .map(|r| {
                    r.targets
                        .iter()
                        .filter_map(|t| self.func_index.get(t).copied())
                        .collect()
                })
                .unwrap_or_default();
            target_map.insert(site, funcs);
        }

        let mut rounds = 0usize;
        let mut pts = self.solve_once(&target_map);
        loop {
            rounds += 1;
            let new_map = self.recompute_targets(&in_scope_sites, &pts);
            // Monotone shrinkage: round k+1 ⊆ round k. A growth is a soundness bug.
            for (&site, funcs) in &new_map {
                let prev: HashSet<usize> = target_map[&site].iter().copied().collect();
                debug_assert!(
                    funcs.iter().all(|f| prev.contains(f)),
                    "Andersen CG-refinement grew an icall target set (soundness bug)"
                );
            }
            if maps_equal(&new_map, &target_map) || rounds >= MAX_ROUNDS {
                break;
            }
            target_map = new_map;
            pts = self.solve_once(&target_map);
        }

        let indirect_calls = self.emit_indirect_calls(&in_scope_sites, &pts);
        let pointee_globals = self.emit_pointee_globals(&pts);
        RefinerOutput {
            indirect_calls,
            pointee_globals,
            rounds,
            oversize_fallbacks: self.oversize_fallbacks,
        }
    }

    // ----- the inclusion solve (stateless per round) ------------------------------------

    /// Solve one fixed call graph from scratch (no caches across rounds). Returns the
    /// points-to set of every in-scope cell.
    fn solve_once(&mut self, target_map: &HashMap<usize, Vec<usize>>) -> Solve {
        let mut solve = Solve::new(self.n_base, self.omega);

        // Base constraints from PAG edges (in-scope only; partitions are self-contained).
        for edge in &self.pag.edges {
            if !self.in_scope[edge.dst.0 as usize] && !self.in_scope[edge.src.0 as usize] {
                continue;
            }
            match edge.kind {
                EdgeKind::AddrOf => solve.add_pts(edge.dst.0, edge.src.0),
                EdgeKind::Assign => solve.add_copy(edge.src.0, edge.dst.0),
                EdgeKind::Load => solve.loads.entry(edge.src.0).or_default().push(edge.dst.0),
                EdgeKind::Store => solve.stores.entry(edge.dst.0).or_default().push(edge.src.0),
                EdgeKind::Gep { byte_off } => solve
                    .geps
                    .entry(edge.src.0)
                    .or_default()
                    .push((byte_off, edge.dst.0)),
                EdgeKind::Memcpy { .. } => solve.memcpys.push((edge.dst.0, edge.src.0)),
            }
        }

        // Ω seeding: in-scope cells whose Steensgaard class is EXT may point to Ω.
        for i in 0..self.n_base {
            if self.in_scope[i] && self.classes.ext[self.classes.class_of(NodeId(i as u32))] {
                solve.add_pts(i as Cell, self.omega);
            }
        }

        // Indirect-call bindings for the fixed call graph (direct calls are already PAG
        // Assign edges; only icalls are bound dynamically).
        for (&site, funcs) in target_map {
            let cs = &self.pag.callsites[site];
            for &f in funcs {
                for (i, &arg) in cs.args.iter().enumerate() {
                    if let Some(&param) = self.param_nodes.get(&(f, i)) {
                        solve.add_copy(arg.0, param.0);
                    }
                }
                if let (Some(result), Some(&ret)) = (cs.result, self.ret_nodes.get(&f)) {
                    solve.add_copy(ret.0, result.0);
                }
            }
        }

        solve.run();
        solve
    }

    /// Recompute each in-scope site's targets = FSA ∩ {address-taken functions in
    /// pts(operand)} from the solved points-to.
    fn recompute_targets(
        &self,
        sites: &[usize],
        pts: &Solve,
    ) -> HashMap<usize, Vec<usize>> {
        let mut map = HashMap::new();
        for &site in sites {
            let cs = &self.pag.callsites[site];
            let operand = cs.operand.unwrap();
            let mut funcs: Vec<usize> = Vec::new();
            if let Some(set) = pts.pts.get(&operand.0) {
                for &cell in set {
                    if let Some(&idx) = self.fn_cell_to_index.get(&cell) {
                        let f = &self.pir.functions[idx];
                        if f.address_taken && fsa_compatible(&cs.sig, &f.sig) {
                            funcs.push(idx);
                        }
                    }
                }
            }
            funcs.sort_unstable();
            funcs.dedup();
            map.insert(site, funcs);
        }
        map
    }

    fn emit_indirect_calls(
        &self,
        in_scope_sites: &[usize],
        pts: &Solve,
    ) -> Vec<IndirectCallResolution> {
        let in_scope: HashSet<usize> = in_scope_sites.iter().copied().collect();
        let final_map = self.recompute_targets(in_scope_sites, pts);
        let mut out = Vec::new();
        for (idx, cs) in self.pag.callsites.iter().enumerate() {
            if cs.kind != CallKind::Indirect {
                continue;
            }
            let steens = self
                .base
                .indirect_calls
                .iter()
                .find(|r| r.callsite_key == cs.key);
            if in_scope.contains(&idx) {
                let mut targets: Vec<String> = final_map
                    .get(&idx)
                    .map(|fs| fs.iter().map(|&i| self.pir.functions[i].key.clone()).collect())
                    .unwrap_or_default();
                targets.sort();
                // M2.0 subset tripwire: a more-exact tier may only narrow. Andersen's
                // per-site targets must be ⊆ the Steensgaard envelope it refined.
                if let Some(steens) = steens {
                    crate::debug_assert_narrows(&cs.key, "andersen", &targets, "steens", &steens.targets);
                }
                out.push(IndirectCallResolution {
                    callsite_key: cs.key.clone(),
                    targets,
                    // Ω/unknown-callee is a Steensgaard escape verdict, kept verbatim.
                    unknown_callee: steens.map(|r| r.unknown_callee).unwrap_or(false),
                    fallback: false,
                });
            } else if let Some(steens) = steens {
                // Uninteresting or oversize partition: keep Steensgaard, tag as fallback.
                out.push(IndirectCallResolution {
                    fallback: true,
                    ..steens.clone()
                });
            }
        }
        out
    }

    fn emit_pointee_globals(&self, pts: &Solve) -> Vec<(String, Vec<String>)> {
        let mut out = Vec::new();
        for node in &self.pag.nodes {
            if !node.kind.is_value_like_public() || !self.in_scope[node.id.0 as usize] {
                continue;
            }
            let Some(set) = pts.pts.get(&node.id.0) else {
                continue;
            };
            let mut globals: Vec<String> = set
                .iter()
                .filter_map(|cell| self.global_of_cell.get(cell))
                .map(|&idx| self.pir.globals[idx].key.clone())
                .collect();
            globals.sort();
            globals.dedup();
            out.push((node.label.clone(), globals));
        }
        out
    }
}

fn maps_equal(a: &HashMap<usize, Vec<usize>>, b: &HashMap<usize, Vec<usize>>) -> bool {
    a.len() == b.len() && a.iter().all(|(k, v)| b.get(k).map(|w| w == v).unwrap_or(false))
}

/// One stateless inclusion solve over a fixed constraint set.
struct Solve {
    omega: Cell,
    next_field: Cell,
    pts: HashMap<Cell, HashSet<Cell>>,
    succ: HashMap<Cell, HashSet<Cell>>,
    loads: HashMap<Cell, Vec<Cell>>,
    stores: HashMap<Cell, Vec<Cell>>,
    geps: HashMap<Cell, Vec<(Option<i64>, Cell)>>,
    memcpys: Vec<(Cell, Cell)>,
    fields: HashMap<(Cell, i64), Cell>,
    /// field cell -> base object cell, so a refined field resolves back to its global.
    field_base: HashMap<Cell, Cell>,
    /// base object cell -> its materialized constant-offset field cells. Needed to
    /// retroactively conflate them when the base later receives a non-constant access (M2.1).
    obj_fields: HashMap<Cell, Vec<Cell>>,
    /// base object cells that have had a non-constant (`⊤`) access — their fields are
    /// conflated with the whole object (the generalization pair, `PLAN-M2_lite_delta.md`
    /// §1 M2.1). A field distinction is unsound once an unknown offset can alias it.
    collapsed: HashSet<Cell>,
    worklist: Vec<Cell>,
    queued: HashSet<Cell>,
}

impl Solve {
    fn new(n_base: usize, omega: Cell) -> Self {
        let mut solve = Self {
            omega,
            next_field: omega + 1,
            pts: HashMap::new(),
            succ: HashMap::new(),
            loads: HashMap::new(),
            stores: HashMap::new(),
            geps: HashMap::new(),
            memcpys: Vec::new(),
            fields: HashMap::new(),
            field_base: HashMap::new(),
            obj_fields: HashMap::new(),
            collapsed: HashSet::new(),
            worklist: Vec::new(),
            queued: HashSet::new(),
        };
        let _ = n_base;
        // Ω is absorbing: it points only to itself.
        solve.pts.entry(omega).or_default().insert(omega);
        solve
    }

    fn enqueue(&mut self, cell: Cell) {
        if self.queued.insert(cell) {
            self.worklist.push(cell);
        }
    }

    fn add_pts(&mut self, cell: Cell, obj: Cell) {
        if cell == self.omega {
            return; // Ω stays {Ω}
        }
        if self.pts.entry(cell).or_default().insert(obj) {
            self.enqueue(cell);
        }
    }

    fn add_copy(&mut self, from: Cell, to: Cell) {
        if to == self.omega || from == to {
            return;
        }
        if self.succ.entry(from).or_default().insert(to) {
            // Push current pts(from) into pts(to) immediately.
            if let Some(src) = self.pts.get(&from).cloned() {
                let mut changed = false;
                let dst = self.pts.entry(to).or_default();
                for o in src {
                    changed |= dst.insert(o);
                }
                if changed {
                    self.enqueue(to);
                }
            }
        }
    }

    /// Field/subobject identity for `base + off` (M2.1, `PLAN-M2_lite_delta.md` §1 M2.1).
    ///
    /// A **constant** offset gets its own subobject cell, giving field sensitivity. A
    /// **non-constant** offset (`None`) is the unknown-offset `⊤` case: it can alias *any*
    /// field of `base`, so we **conflate** `base`'s fields with the whole-object cell and
    /// route the access there. This is the generalization pair recast as a collapse — it is
    /// the principled fix for the M1.4b false negative where a value stored through a
    /// dynamic-index GEP was invisible to a constant-offset load of the same object. The
    /// collapse is sound (a superset) and only touches objects actually indexed by an
    /// unknown offset; all-constant objects keep full field precision.
    fn field_of(&mut self, base: Cell, off: Option<i64>) -> Cell {
        if base == self.omega {
            return self.omega;
        }
        if self.collapsed.contains(&base) {
            // Every access to a `⊤`-collapsed object names the whole-object cell.
            return base;
        }
        match off {
            None => {
                self.collapse(base);
                base
            }
            Some(off) => {
                if let Some(&cell) = self.fields.get(&(base, off)) {
                    return cell;
                }
                let cell = self.next_field;
                self.next_field += 1;
                self.fields.insert((base, off), cell);
                // A field of a field still ultimately names the original base object.
                let root = self.field_base.get(&base).copied().unwrap_or(base);
                self.field_base.insert(cell, root);
                self.obj_fields.entry(base).or_default().push(cell);
                cell
            }
        }
    }

    /// Mark `base` as `⊤`-accessed and conflate its already-materialized field cells with
    /// the whole-object cell, in both directions: a value stored to any field becomes
    /// visible to the unknown-offset access, and vice versa. Idempotent; future fields of a
    /// collapsed object route straight to `base` via `field_of`.
    fn collapse(&mut self, base: Cell) {
        if !self.collapsed.insert(base) {
            return;
        }
        if let Some(fields) = self.obj_fields.get(&base).cloned() {
            for f in fields {
                self.add_copy(f, base);
                self.add_copy(base, f);
            }
        }
    }

    fn run(&mut self) {
        // Prime the worklist with every cell that already has points-to facts.
        let seeded: Vec<Cell> = self.pts.keys().copied().collect();
        for c in seeded {
            self.enqueue(c);
        }

        while let Some(n) = self.worklist.pop() {
            self.queued.remove(&n);
            let objs: Vec<Cell> = self.pts.get(&n).map(|s| s.iter().copied().collect()).unwrap_or_default();

            // n as a load base: p = *n  ⇒  pts(o) ⊆ pts(p)  for o ∈ pts(n)
            if let Some(ps) = self.loads.get(&n).cloned() {
                for p in ps {
                    for &o in &objs {
                        self.add_copy(o, p);
                    }
                }
            }
            // n as a store base: *n = q  ⇒  pts(q) ⊆ pts(o)  for o ∈ pts(n)
            if let Some(qs) = self.stores.get(&n).cloned() {
                for q in qs {
                    for &o in &objs {
                        self.add_copy(q, o);
                    }
                }
            }
            // n as a gep base: p = n + off  ⇒  field(o, off) ∈ pts(p)  for o ∈ pts(n)
            if let Some(gs) = self.geps.get(&n).cloned() {
                for (off, p) in gs {
                    for &o in &objs {
                        let f = self.field_of(o, off);
                        self.add_pts(p, f);
                    }
                }
            }
            // n in a memcpy: contents-copy between pointed-to objects (field-insensitive).
            if !self.memcpys.is_empty() {
                let relevant: Vec<(Cell, Cell)> = self
                    .memcpys
                    .iter()
                    .copied()
                    .filter(|&(d, s)| d == n || s == n)
                    .collect();
                for (d, s) in relevant {
                    let dobjs: Vec<Cell> = self.pts.get(&d).map(|s| s.iter().copied().collect()).unwrap_or_default();
                    let sobjs: Vec<Cell> = self.pts.get(&s).map(|s| s.iter().copied().collect()).unwrap_or_default();
                    for &od in &dobjs {
                        for &os in &sobjs {
                            self.add_copy(os, od);
                        }
                    }
                }
            }
            // Propagate along copy edges.
            if let Some(succs) = self.succ.get(&n).cloned() {
                let src: HashSet<Cell> = self.pts.get(&n).cloned().unwrap_or_default();
                for s in succs {
                    if s == self.omega {
                        continue;
                    }
                    let mut changed = false;
                    let dst = self.pts.entry(s).or_default();
                    for &o in &src {
                        changed |= dst.insert(o);
                    }
                    if changed {
                        self.enqueue(s);
                    }
                }
            }
        }
    }
}

// `NodeKind::is_value_like` is private in pangs-pag; mirror it here.
trait ValueLike {
    fn is_value_like_public(&self) -> bool;
}
impl ValueLike for NodeKind {
    fn is_value_like_public(&self) -> bool {
        matches!(
            self,
            NodeKind::Value { .. } | NodeKind::Param { .. } | NodeKind::Return { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use pangs_pag::{BuildMode, Pag, PagOpts};
    use pangs_pir::Pir;

    use super::solve_andersen;
    use crate::solve_steensgaard;

    fn fixture(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/synthetic/m1_4b")
            .join(name)
    }

    fn load(name: &str) -> (Pir, Pag) {
        let pir = Pir::from_path(fixture(name)).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        (pir, pag)
    }

    fn load_m2_1(name: &str) -> (Pir, Pag) {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/synthetic/m2_1")
            .join(name);
        let pir = Pir::from_path(path).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        (pir, pag)
    }

    #[test]
    fn m2_1_dynamic_store_is_seen_by_constant_load() {
        // The (o,⊤) generalization: a value written through a non-constant-offset GEP must
        // reach a constant-offset load of the same object. Before M2.1, andersen dropped it.
        let (pir, pag) = load_m2_1("dynamic_store_const_load.pir.json");
        let steens = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert_eq!(steens.indirect_calls[0].targets, vec!["alpha".to_string()]);
        let andersen = solve_andersen(&pir, &pag, BuildMode::Library, 1_000_000);
        assert_eq!(
            andersen.indirect_calls[0].targets,
            vec!["alpha".to_string()],
            "M2.1: dynamic-offset store must be visible to a constant-offset load"
        );
    }

    #[test]
    fn m2_1_constant_store_is_seen_by_dynamic_load() {
        // Reverse direction: a constant-offset store must reach a non-constant (⊤) load.
        let (pir, pag) = load_m2_1("const_store_dynamic_load.pir.json");
        let steens = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert_eq!(steens.indirect_calls[0].targets, vec!["beta".to_string()]);
        let andersen = solve_andersen(&pir, &pag, BuildMode::Library, 1_000_000);
        assert_eq!(
            andersen.indirect_calls[0].targets,
            vec!["beta".to_string()],
            "M2.1: constant-offset store must be visible to a non-constant-offset load"
        );
    }

    #[test]
    fn andersen_distinguishes_struct_fn_ptr_fields() {
        let (pir, pag) = load("field_sensitive_fnptr.pir.json");

        // Steensgaard conflates the two struct fields → both targets.
        let steens = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert_eq!(steens.indirect_calls.len(), 1);
        assert_eq!(
            steens.indirect_calls[0].targets,
            vec!["f0".to_string(), "f1".to_string()]
        );

        // Andersen's field sensitivity keeps only the field actually loaded.
        let andersen = solve_andersen(&pir, &pag, BuildMode::Library, 1_000_000);
        assert_eq!(andersen.indirect_calls.len(), 1);
        assert_eq!(andersen.indirect_calls[0].targets, vec!["f0".to_string()]);
        assert!(!andersen.indirect_calls[0].fallback);
        // Narrowing ledger: andersen ⊆ steens.
        assert!(andersen.indirect_calls[0]
            .targets
            .iter()
            .all(|t| steens.indirect_calls[0].targets.contains(t)));
        assert!(andersen.metrics.rounds >= 1);
    }

    #[test]
    fn cg_refinement_drops_an_edge_in_a_later_round() {
        let (pir, pag) = load("cg_refinement.pir.json");

        let steens = solve_steensgaard(&pir, &pag, BuildMode::Library);
        let steens_b = steens
            .indirect_calls
            .iter()
            .find(|r| r.callsite_key == "dispatchB@!noloc#0")
            .unwrap();
        // Round-0 (Steensgaard) call graph routes g into dispatchB's parameter.
        assert_eq!(steens_b.targets, vec!["g".to_string()]);

        let andersen = solve_andersen(&pir, &pag, BuildMode::Library, 1_000_000);
        // Outer site narrows to dispatchA only…
        let outer = andersen
            .indirect_calls
            .iter()
            .find(|r| r.callsite_key == "setup@!noloc#0")
            .unwrap();
        assert_eq!(outer.targets, vec!["dispatchA".to_string()]);
        // …which removes the g→dispatchB.cb binding, dropping dispatchB's inner edge.
        let andersen_b = andersen
            .indirect_calls
            .iter()
            .find(|r| r.callsite_key == "dispatchB@!noloc#0")
            .unwrap();
        assert!(
            andersen_b.targets.is_empty(),
            "expected dispatchB inner edge dropped, got {:?}",
            andersen_b.targets
        );
        // dispatchA's inner edge survives.
        let andersen_a = andersen
            .indirect_calls
            .iter()
            .find(|r| r.callsite_key == "dispatchA@!noloc#0")
            .unwrap();
        assert_eq!(andersen_a.targets, vec!["g".to_string()]);
        // The drop only happens because the loop ran a second round.
        assert!(andersen.metrics.rounds >= 2, "rounds={}", andersen.metrics.rounds);
    }

    #[test]
    fn andersen_subset_of_steensgaard_and_terminates_on_suite() {
        // Walk every solver fixture and assert the narrowing ledger holds and the
        // CG-refinement loop converges within the round budget.
        let roots = ["m1_4", "m1_4b", "m1_5"];
        let mut checked = 0;
        for root in roots {
            let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/synthetic")
                .join(root);
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                let pir = Pir::from_path(&path).unwrap();
                let pag = Pag::from_pir(&pir, &PagOpts::default());
                let steens = solve_steensgaard(&pir, &pag, BuildMode::Library);
                let andersen = solve_andersen(&pir, &pag, BuildMode::Library, 1_000_000);

                let steens_by_key: std::collections::HashMap<_, _> = steens
                    .indirect_calls
                    .iter()
                    .map(|r| (r.callsite_key.as_str(), r))
                    .collect();
                for a in &andersen.indirect_calls {
                    let s = steens_by_key.get(a.callsite_key.as_str()).unwrap();
                    for t in &a.targets {
                        assert!(
                            s.targets.contains(t),
                            "{}: andersen target {} not in steens for {} (ledger break)",
                            path.display(),
                            t,
                            a.callsite_key
                        );
                    }
                }
                assert!(
                    andersen.metrics.rounds <= 4,
                    "{}: {} rounds exceeds budget",
                    path.display(),
                    andersen.metrics.rounds
                );
                checked += 1;
            }
        }
        assert!(checked >= 10, "expected to check ≥10 fixtures, got {checked}");
    }

    #[test]
    fn two_global_fnptrs_through_memory_resolve_both_sites() {
        // Regression for the Steensgaard over-merge bug (ju_steens_overmerge_bug.md):
        // two distinct global function pointers stored and loaded through memory in the
        // same function form a cyclic pointee structure. The `join` recursion used to
        // re-parent the destination root and orphan the merged pointee link, dropping the
        // *second* icall site to empty targets with no `unknown_callee` — a silent false
        // negative. Both sites must now resolve to their single target on both stages.
        let (pir, pag) = load("two_global_fnptrs.pir.json");

        let steens = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert_eq!(steens.indirect_calls.len(), 2);
        for r in &steens.indirect_calls {
            assert_eq!(r.targets.len(), 1, "steens dropped {}: {:?}", r.callsite_key, r.targets);
            // Soundness: a resolved site must never be empty-without-unknown_callee.
            assert!(!(r.targets.is_empty() && !r.unknown_callee));
        }
        let steens_targets: Vec<&str> = steens
            .indirect_calls
            .iter()
            .flat_map(|r| r.targets.iter().map(|t| t.as_str()))
            .collect();
        assert!(steens_targets.contains(&"alpha"));
        assert!(steens_targets.contains(&"beta"));

        let andersen = solve_andersen(&pir, &pag, BuildMode::Library, 1_000_000);
        assert_eq!(andersen.indirect_calls.len(), 2);
        for r in &andersen.indirect_calls {
            assert_eq!(r.targets.len(), 1, "andersen dropped {}: {:?}", r.callsite_key, r.targets);
        }
    }

    #[test]
    fn oversize_budget_falls_back_to_steensgaard() {
        let (pir, pag) = load("field_sensitive_fnptr.pir.json");
        // A zero budget forces every partition oversize → Steensgaard answer, tagged fallback.
        let andersen = solve_andersen(&pir, &pag, BuildMode::Library, 0);
        assert_eq!(andersen.indirect_calls.len(), 1);
        assert!(andersen.indirect_calls[0].fallback);
        assert_eq!(
            andersen.indirect_calls[0].targets,
            vec!["f0".to_string(), "f1".to_string()]
        );
        assert!(andersen.metrics.oversize_fallbacks >= 1);
    }
}
