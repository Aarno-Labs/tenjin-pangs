//! Indirect-call provenance census (diagnostic only).
//!
//! Two measurements, both purely observational — nothing here feeds the PAG, the solvers,
//! disposition, or any soundness guard:
//!
//! 1. **Operand provenance taxonomy.** For every indirect callsite, a bounded backward walk
//!    over the enclosing function's PIR statements classifies *how the function-pointer
//!    operand was produced*: a materialized `&f`, a formal parameter, a load from a global
//!    table, a load through a parameter-reachable object, a call result, and so on.
//!    `DESIGN_lite.md` §4 asserts a distribution over exactly this taxonomy ("the icalls that
//!    shape the localization client's component structure are dispatch tables … the
//!    parameter-passed cases are Ω-frozen regardless"), and §5's upgrade gates ask which
//!    bucket dominates. This makes that a count instead of a judgement.
//!
//! 2. **FSA intersection.** Per site: the size of the FSA signature envelope, the size of the
//!    pointer answer, and how many callees the pointer solution proposed that only the type
//!    envelope excluded (`IcallFsaCensus`). The debug tripwires assert `Andersen ⊆ FSA` and
//!    fail; this counts the disagreement instead of asserting it away.
//!
//! The walk is deliberately **intraprocedural**. It reports where an operand's producers
//! leave the frame (`param`, `call_return`, …) rather than chasing them across it, so each
//! label is a local, deterministic fact about one function body — the same shape as the
//! `parameter_call`/`structure_call` counters in the Clash artifact.

use std::collections::{BTreeSet, HashMap, HashSet};

use pangs_pir::{fsa_compatible, Pir, Stmt};

/// Visited-value cap per callsite. A walk that hits it is reported `truncated` rather than
/// silently returning a partial label set.
const MAX_VISITED: usize = 4096;

/// One provenance label. A site carries the *set* of labels its producers reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Label {
    /// `&f` materialized in this frame (a function symbol operand).
    FnAddress,
    /// A formal parameter of the enclosing function — the operand is produced by the caller.
    Param,
    /// Load from a place rooted at a global: dispatch tables, handler registries.
    GlobalLoad,
    /// Load through an object reachable from a formal parameter: `self->handler` dispatch.
    ParamDerefLoad,
    /// Load from a local aggregate that is not a promotable scalar slot.
    AllocaLoad,
    /// Load through an object returned by a direct call — typically heap allocated.
    CallResultLoad,
    /// Load whose address itself came out of memory: `a->b->fn`.
    ChainedLoad,
    /// Load whose address root could not be classified.
    OtherLoad,
    /// Result of a direct call to an internal function (a factory or accessor).
    CallReturn,
    /// Result of a direct call to an external function.
    ExternalReturn,
    /// Result of another indirect call.
    IcallReturn,
    /// Reached an integer conversion or arithmetic: a forged address.
    IntForged,
    /// Reached a `va_arg`.
    VarArg,
    /// Reached an unmodeled instruction.
    UnknownStmt,
    /// A global data symbol used directly as the callee operand.
    GlobalSymbol,
    /// Load whose address is an *unlowered LLVM constant expression* naming a global — the
    /// `g_table[1]` dispatch-table shape, which PIR keeps as opaque operand text rather than
    /// decomposing into a `Gep`. Counted separately from `global_load` so the report can show
    /// how much of the dispatch-table bucket rests on reading that text.
    ConstExprGlobalLoad,
    /// The operand has no definition in this frame (and is not a parameter).
    Undefined,
}

impl Label {
    pub fn name(self) -> &'static str {
        match self {
            Label::FnAddress => "fn_address",
            Label::Param => "param",
            Label::GlobalLoad => "global_load",
            Label::ParamDerefLoad => "param_deref_load",
            Label::AllocaLoad => "alloca_load",
            Label::CallResultLoad => "call_result_load",
            Label::ChainedLoad => "chained_load",
            Label::OtherLoad => "other_load",
            Label::CallReturn => "call_return",
            Label::ExternalReturn => "external_return",
            Label::IcallReturn => "icall_return",
            Label::IntForged => "int_forged",
            Label::VarArg => "vararg",
            Label::UnknownStmt => "unknown_stmt",
            Label::GlobalSymbol => "global_symbol",
            Label::ConstExprGlobalLoad => "constexpr_global_load",
            Label::Undefined => "undefined",
        }
    }

    /// Bucket priority: lower wins when a site carries several labels.
    ///
    /// The order answers "which mechanism would have to resolve this site", worst first:
    /// an opaque producer is beyond every planned refinement; a parameter-passed pointer is
    /// the context-sensitivity case (`DESIGN_lite.md` §4); a load through a parameter-reachable
    /// object is the receiver/vtable case receiver-payload summaries target; a global-table
    /// load is what B1 InitVal plus the dispatch-table carve-out already settles; a
    /// materialized `&f` is what B2 resolves exactly.
    fn bucket_rank(self) -> u8 {
        match self {
            Label::IntForged | Label::UnknownStmt | Label::VarArg | Label::Undefined => 0,
            Label::GlobalSymbol | Label::OtherLoad | Label::ChainedLoad => 1,
            Label::IcallReturn | Label::ExternalReturn => 2,
            Label::Param => 3,
            Label::ParamDerefLoad => 4,
            Label::CallResultLoad | Label::AllocaLoad => 5,
            Label::CallReturn => 6,
            Label::GlobalLoad | Label::ConstExprGlobalLoad => 7,
            Label::FnAddress => 8,
        }
    }

    /// Coarse bucket name for the headline histogram.
    fn bucket(self) -> &'static str {
        match self {
            Label::IntForged | Label::UnknownStmt | Label::VarArg | Label::Undefined => "opaque",
            Label::GlobalSymbol | Label::OtherLoad | Label::ChainedLoad => "unclassified_memory",
            Label::IcallReturn | Label::ExternalReturn => "external_or_icall_return",
            Label::Param => "param_passed",
            Label::ParamDerefLoad => "param_deref",
            Label::CallResultLoad | Label::AllocaLoad => "local_or_heap_object",
            Label::CallReturn => "factory_return",
            Label::GlobalLoad | Label::ConstExprGlobalLoad => "dispatch_table",
            Label::FnAddress => "direct_address",
        }
    }
}

/// Per-callsite census row.
///
/// Rows carry no callsite key: they are produced in the same order `Analysis` builds its
/// callsite table (module function order, then body order), so consumers join them
/// positionally against `analysis.callsites()` filtered to indirect calls. Recomputing the
/// key scheme here would be a second, independently driftable definition of it — exactly the
/// failure `push_callsite`'s comment records.
#[derive(Debug, Clone)]
pub struct CensusRow {
    pub caller: String,
    pub labels: BTreeSet<Label>,
    pub bucket: &'static str,
    pub truncated: bool,
    /// Address-taken functions signature-compatible with this site (the FSA envelope).
    pub fsa_envelope: usize,
}

/// Per-function index supporting the walk.
struct FuncIndex<'a> {
    /// value name -> defining statement index
    defs: HashMap<&'a str, usize>,
    /// parameter name -> index
    params: HashMap<&'a str, usize>,
    /// allocas used *only* as a load/store address: promotable scalar slots. Unoptimized
    /// bitcode routes every local through one of these, so the taxonomy would otherwise
    /// report `alloca_load` for the whole -O0 half of a corpus and measure `mem2reg`
    /// rather than program structure.
    slots: HashSet<&'a str>,
    /// slot name -> values stored into it
    slot_stores: HashMap<&'a str, Vec<&'a str>>,
}

impl<'a> FuncIndex<'a> {
    fn build(func: &'a pangs_pir::Func) -> Self {
        let mut defs = HashMap::new();
        for (index, stmt) in func.body.iter().enumerate() {
            if let Some(dest) = stmt_dest(stmt) {
                defs.insert(dest, index);
            }
        }
        let params = func
            .param_names
            .iter()
            .enumerate()
            .map(|(index, name)| (name.as_str(), index))
            .collect();

        let mut allocas = HashSet::new();
        for stmt in &func.body {
            if let Stmt::Alloca { dest, .. } = stmt {
                allocas.insert(dest.as_str());
            }
        }
        // Any appearance outside a load/store *address* position disqualifies the slot.
        let mut disqualified = HashSet::new();
        for stmt in &func.body {
            for_each_capturing_operand(stmt, &mut |name| {
                disqualified.insert(name);
            });
        }
        let slots: HashSet<&str> = allocas
            .into_iter()
            .filter(|name| !disqualified.contains(name))
            .collect();

        let mut slot_stores: HashMap<&str, Vec<&str>> = HashMap::new();
        for stmt in &func.body {
            if let Stmt::Store { address, value, .. } = stmt {
                if slots.contains(address.as_str()) {
                    slot_stores
                        .entry(address.as_str())
                        .or_default()
                        .push(value.as_str());
                }
            }
        }

        Self {
            defs,
            params,
            slots,
            slot_stores,
        }
    }
}

/// Calls `visit` for every operand position that could *capture* the named value — that is,
/// every position except a load or store **address**. A local whose every use is a load or
/// store address is a promotable scalar slot.
fn for_each_capturing_operand<'a>(stmt: &'a Stmt, visit: &mut impl FnMut(&'a str)) {
    match stmt {
        Stmt::Alloca { .. } | Stmt::VarArg { .. } | Stmt::GlobalRef { .. } => {}
        Stmt::Assign { sources, .. } => sources.iter().for_each(|s| visit(s)),
        Stmt::ScalarOp { lhs, rhs, .. } => {
            visit(lhs);
            visit(rhs);
        }
        Stmt::Load { .. } => {}
        Stmt::Store { value, .. } => visit(value),
        Stmt::Gep { base, .. } => visit(base),
        Stmt::PtrToInt { source, .. } | Stmt::IntToPtr { source, .. } => visit(source),
        Stmt::Memcpy { dst, src, .. } => {
            visit(dst);
            visit(src);
        }
        Stmt::Memset { dst, value, .. } => {
            visit(dst);
            visit(value);
        }
        Stmt::Unknown { operands, .. } => operands.iter().for_each(|o| visit(o)),
        Stmt::Return { value, .. } => {
            if let Some(value) = value {
                visit(value);
            }
        }
        Stmt::CallDirect { args, .. } => args.iter().for_each(|a| visit(a)),
        Stmt::CallIndirect { operand, args, .. } => {
            visit(operand);
            args.iter().for_each(|a| visit(a));
        }
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
        Stmt::Store { .. }
        | Stmt::Memcpy { .. }
        | Stmt::Memset { .. }
        | Stmt::Unknown { .. }
        | Stmt::Return { .. }
        | Stmt::GlobalRef { .. } => None,
    }
}

struct Walker<'a> {
    functions: HashSet<&'a str>,
    globals: HashSet<&'a str>,
    external: HashSet<&'a str>,
}

impl<'a> Walker<'a> {
    fn new(module: &'a Pir) -> Self {
        Self {
            functions: module.functions.iter().map(|f| f.key.as_str()).collect(),
            globals: module.globals.iter().map(|g| g.key.as_str()).collect(),
            external: module
                .functions
                .iter()
                .filter(|f| f.external)
                .map(|f| f.key.as_str())
                .collect(),
        }
    }

    /// PIR spells a symbol *operand* `@name` while `Func::key`/`Global::key` are bare, so
    /// every symbol test has to strip the sigil before looking the name up.
    fn is_function(&self, value: &str) -> bool {
        value
            .strip_prefix('@')
            .is_some_and(|name| self.functions.contains(name))
    }

    fn is_global(&self, value: &str) -> bool {
        value
            .strip_prefix('@')
            .is_some_and(|name| self.globals.contains(name))
    }

    /// True when an operand PIR could not lower — an LLVM constant expression kept as text —
    /// mentions a module global. `getelementptr inbounds (… @g_table, i64 0, i64 1)` is the
    /// constant-indexed dispatch-table address; without this the site would be filed under
    /// `other_load` and the dispatch-table bucket would be undercounted.
    fn names_global(&self, value: &str) -> bool {
        self.embedded_symbols(value)
            .any(|name| self.globals.contains(name))
    }

    /// As `names_global`, for function symbols: a constant `bitcast`/`gep` wrapping `@f`.
    fn names_function(&self, value: &str) -> bool {
        self.embedded_symbols(value)
            .any(|name| self.functions.contains(name))
    }

    fn embedded_symbols<'v>(&self, value: &'v str) -> impl Iterator<Item = &'v str> {
        value.match_indices('@').filter_map(|(at, _)| {
            let rest = &value[at + 1..];
            let end = rest
                .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '.' || c == '$'))
                .unwrap_or(rest.len());
            (end > 0).then(|| &rest[..end])
        })
    }

    /// Classify the operand of one indirect call inside `func`.
    fn classify(
        &self,
        func: &'a pangs_pir::Func,
        index: &FuncIndex<'a>,
        operand: &'a str,
    ) -> (BTreeSet<Label>, bool) {
        let mut labels = BTreeSet::new();
        let mut visited = HashSet::new();
        let mut queue = vec![operand];
        let mut truncated = false;

        while let Some(value) = queue.pop() {
            if visited.len() >= MAX_VISITED {
                truncated = true;
                break;
            }
            if !visited.insert(value) {
                continue;
            }
            self.step(func, index, value, &mut labels, &mut queue);
        }
        (labels, truncated)
    }

    fn step(
        &self,
        func: &'a pangs_pir::Func,
        index: &FuncIndex<'a>,
        value: &'a str,
        labels: &mut BTreeSet<Label>,
        queue: &mut Vec<&'a str>,
    ) {
        if self.is_function(value) {
            labels.insert(Label::FnAddress);
            return;
        }
        if self.is_global(value) {
            labels.insert(Label::GlobalSymbol);
            return;
        }
        if index.params.contains_key(value) {
            labels.insert(Label::Param);
            return;
        }
        let Some(&stmt_index) = index.defs.get(value) else {
            // An operand PIR could not lower is kept as LLVM constant-expression text.
            // Read the symbol out of it rather than filing a real producer as `undefined`.
            if self.names_function(value) {
                labels.insert(Label::FnAddress);
            } else if self.names_global(value) {
                labels.insert(Label::GlobalSymbol);
            } else {
                labels.insert(Label::Undefined);
            }
            return;
        };
        match &func.body[stmt_index] {
            // Copies, casts, phis and selects are transparent.
            Stmt::Assign { sources, .. } => {
                if sources.is_empty() {
                    labels.insert(Label::Undefined);
                }
                queue.extend(sources.iter().map(String::as_str));
            }
            Stmt::Gep { base, .. } => queue.push(base),
            Stmt::Load { address, .. } => self.classify_load(func, index, address, labels, queue),
            Stmt::CallDirect { callee, .. } => {
                if self.external.contains(callee.as_str()) {
                    labels.insert(Label::ExternalReturn);
                } else {
                    labels.insert(Label::CallReturn);
                }
            }
            Stmt::CallIndirect { .. } => {
                labels.insert(Label::IcallReturn);
            }
            Stmt::IntToPtr { .. } | Stmt::PtrToInt { .. } | Stmt::ScalarOp { .. } => {
                labels.insert(Label::IntForged);
            }
            Stmt::VarArg { .. } => {
                labels.insert(Label::VarArg);
            }
            Stmt::Unknown { .. } => {
                labels.insert(Label::UnknownStmt);
            }
            // An alloca address called as a function, or a non-defining statement reached
            // through a stale definition map: neither is a producer we can name.
            Stmt::Alloca { .. }
            | Stmt::Store { .. }
            | Stmt::Memcpy { .. }
            | Stmt::Memset { .. }
            | Stmt::Return { .. }
            | Stmt::GlobalRef { .. } => {
                labels.insert(Label::OtherLoad);
            }
        }
    }

    /// A load is classified by the storage root(s) of its **address**, which is what says
    /// whether the pointer came out of a global table, a parameter-reachable object, or a
    /// heap object.
    fn classify_load(
        &self,
        func: &'a pangs_pir::Func,
        index: &FuncIndex<'a>,
        address: &'a str,
        labels: &mut BTreeSet<Label>,
        queue: &mut Vec<&'a str>,
    ) {
        // A load straight out of a promotable scalar slot is not a memory producer at all —
        // it is the unoptimized spelling of an SSA copy. Continue into the stored values.
        if index.slots.contains(address) {
            match index.slot_stores.get(address) {
                Some(values) => queue.extend(values.iter().copied()),
                // A slot that is only ever read holds undef.
                None => {
                    labels.insert(Label::Undefined);
                }
            }
            return;
        }
        for root in self.address_roots(func, index, address) {
            labels.insert(self.root_label(func, index, root));
        }
    }

    fn root_label(&self, func: &'a pangs_pir::Func, index: &FuncIndex<'a>, root: &'a str) -> Label {
        if self.is_global(root) {
            return Label::GlobalLoad;
        }
        if index.params.contains_key(root) {
            return Label::ParamDerefLoad;
        }
        let Some(&stmt_index) = index.defs.get(root) else {
            return if self.names_global(root) {
                Label::ConstExprGlobalLoad
            } else {
                Label::OtherLoad
            };
        };
        match &func.body[stmt_index] {
            Stmt::Alloca { .. } => Label::AllocaLoad,
            Stmt::CallDirect { .. } | Stmt::CallIndirect { .. } => Label::CallResultLoad,
            Stmt::Load { .. } => Label::ChainedLoad,
            Stmt::IntToPtr { .. } | Stmt::PtrToInt { .. } | Stmt::ScalarOp { .. } => {
                Label::IntForged
            }
            Stmt::Unknown { .. } => Label::UnknownStmt,
            _ => Label::OtherLoad,
        }
    }

    /// The storage roots an address expression can denote.
    ///
    /// Transparent through GEPs, copies/phis, and loads from promotable scalar slots. That
    /// last step is what keeps the taxonomy stable across optimization levels: without it an
    /// unoptimized `p = malloc(); ...; p->fn()` reports `chained_load` (the reload of `p`'s
    /// stack slot) where the `mem2reg`-ed build of the same source reports `call_result_load`,
    /// and the census would be measuring the compiler rather than the program.
    fn address_roots(
        &self,
        func: &'a pangs_pir::Func,
        index: &FuncIndex<'a>,
        address: &'a str,
    ) -> BTreeSet<&'a str> {
        let mut roots = BTreeSet::new();
        let mut visited = HashSet::new();
        let mut queue = vec![address];
        while let Some(value) = queue.pop() {
            if visited.len() >= MAX_VISITED {
                break;
            }
            if !visited.insert(value) {
                continue;
            }
            if self.is_global(value) || index.params.contains_key(value) {
                roots.insert(value);
                continue;
            }
            let Some(&stmt_index) = index.defs.get(value) else {
                roots.insert(value);
                continue;
            };
            match &func.body[stmt_index] {
                Stmt::Gep { base, .. } => queue.push(base),
                Stmt::Assign { sources, .. } if !sources.is_empty() => {
                    queue.extend(sources.iter().map(String::as_str));
                }
                Stmt::Load { address, .. } if index.slots.contains(address.as_str()) => {
                    match index.slot_stores.get(address.as_str()) {
                        Some(values) => queue.extend(values.iter().copied()),
                        None => {
                            roots.insert(value);
                        }
                    }
                }
                _ => {
                    roots.insert(value);
                }
            }
        }
        roots
    }
}

/// Classify every indirect callsite in `module`, in `Analysis` callsite-table order.
pub fn classify_icalls(module: &Pir) -> Vec<CensusRow> {
    let walker = Walker::new(module);
    let address_taken: Vec<&pangs_pir::Func> = module
        .functions
        .iter()
        .filter(|func| func.address_taken)
        .collect();

    let mut rows = Vec::new();
    for func in &module.functions {
        let index = FuncIndex::build(func);
        for stmt in &func.body {
            let Stmt::CallIndirect { operand, sig, .. } = stmt else {
                continue;
            };
            let (labels, truncated) = walker.classify(func, &index, operand.as_str());
            let bucket = labels
                .iter()
                .min_by_key(|label| label.bucket_rank())
                .map(|label| label.bucket())
                .unwrap_or("opaque");
            let fsa_envelope = address_taken
                .iter()
                .filter(|target| fsa_compatible(sig, &target.sig))
                .count();
            rows.push(CensusRow {
                caller: func.key.clone(),
                labels,
                bucket,
                truncated,
                fsa_envelope,
            });
        }
    }
    rows
}
