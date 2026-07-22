//! Use-sensitive validation for LLVM `ptrtoint` instructions.
//!
//! Integerizing a pointer is not itself evidence that the pointer representation escapes.  This
//! module proves two deliberately narrow classes of harmless uses:
//!
//! * a closed integer computation whose only terminal operation is a comparison; and
//! * a subtraction of two pointer representations with one common structural provenance root.
//!
//! The second class is relocation-invariant: translating the common base translates both
//! operands equally, so their modular integer difference is unchanged.  Once that cancellation
//! has been proved, the resulting offset may be stored, returned, or passed to other code without
//! exposing either original pointer representation.  Unknown provenance fails closed.

use std::collections::{BTreeMap, BTreeSet};

use llvm_sys::core::*;
use llvm_sys::prelude::*;
use llvm_sys::{LLVMOpcode, LLVMTypeKind};

use crate::external_return_alias_arg;

use super::{direct_symbol_name, strip_pointer_casts};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PtrToIntUse {
    EscapingOrUnknown,
    ClosedComparison,
    CommonProvenanceDifference,
}

impl PtrToIntUse {
    pub(super) fn is_innocuous(self) -> bool {
        !matches!(self, Self::EscapingOrUnknown)
    }
}

/// Classify a conversion using only facts that are preserved in LLVM IR.  This is intentionally
/// independent of PIR lowering so all ptr/int policy remains in one place.
pub(super) unsafe fn classify(value: LLVMValueRef) -> PtrToIntUse {
    if has_common_provenance_pointer_difference_uses(value) {
        PtrToIntUse::CommonProvenanceDifference
    } else if has_closed_comparison_uses(value) {
        PtrToIntUse::ClosedComparison
    } else {
        PtrToIntUse::EscapingOrUnknown
    }
}

/// Proves that a `ptrtoint` result remains inside the small integer domain whose only terminal
/// operation is `icmp`. Unknown users fail closed. Cyclic phi graphs are accepted only when every
/// edge leaving the cycle eventually reaches a supported comparison/arithmetic node.
unsafe fn has_closed_comparison_uses(value: LLVMValueRef) -> bool {
    unsafe fn visit(
        value: LLVMValueRef,
        visiting: &mut BTreeSet<usize>,
        memo: &mut BTreeMap<usize, bool>,
    ) -> bool {
        let key = value as usize;
        if let Some(&closed) = memo.get(&key) {
            return closed;
        }
        if !visiting.insert(key) {
            return true;
        }

        let mut current_use = LLVMGetFirstUse(value);
        let mut closed = true;
        while !current_use.is_null() {
            let user = LLVMGetUser(current_use);
            if user.is_null() || LLVMIsAInstruction(user).is_null() {
                closed = false;
                break;
            }
            closed = match LLVMGetInstructionOpcode(user) {
                LLVMOpcode::LLVMICmp => true,
                LLVMOpcode::LLVMAdd
                | LLVMOpcode::LLVMSub
                | LLVMOpcode::LLVMAnd
                | LLVMOpcode::LLVMOr
                | LLVMOpcode::LLVMXor
                | LLVMOpcode::LLVMPHI
                | LLVMOpcode::LLVMSelect => visit(user, visiting, memo),
                _ => false,
            };
            if !closed {
                break;
            }
            current_use = LLVMGetNextUse(current_use);
        }

        visiting.remove(&key);
        memo.insert(key, closed);
        closed
    }

    visit(value, &mut BTreeSet::new(), &mut BTreeMap::new())
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PointerOrigins {
    /// Non-null structural roots. Parameters, allocations, and global objects are distinct roots.
    roots: BTreeSet<usize>,
    /// Null is tracked separately because a source-level pointer difference is meaningful only on
    /// executions where both operands designate one array object. Clang commonly leaves a null
    /// initializer in an O0 pointer spill even after control flow has established a non-null value.
    nullable: bool,
}

impl PointerOrigins {
    fn one_common_root(&self, other: &Self) -> bool {
        self.roots.len() == 1 && self.roots == other.roots
    }

    fn merge(&mut self, other: Self) {
        self.roots.extend(other.roots);
        self.nullable |= other.nullable;
    }
}

/// Recover a structural base for a pointer. Loads from nonescaping local pointer spills are
/// handled by enumerating every stored value; arbitrary memory loads and calls fail closed.
unsafe fn pointer_origins(
    value: LLVMValueRef,
    visiting_values: &mut BTreeSet<usize>,
    visiting_slots: &mut BTreeSet<usize>,
    memo: &mut BTreeMap<usize, Option<PointerOrigins>>,
) -> Option<PointerOrigins> {
    let value = strip_pointer_casts(value);
    let key = value as usize;
    if let Some(origins) = memo.get(&key) {
        return origins.clone();
    }
    if !visiting_values.insert(key) {
        return None;
    }

    let result = if !LLVMIsAConstantPointerNull(value).is_null() || LLVMIsNull(value) != 0 {
        Some(PointerOrigins {
            roots: BTreeSet::new(),
            nullable: true,
        })
    } else if !LLVMIsAArgument(value).is_null()
        || !LLVMIsAGlobalValue(value).is_null()
        || !LLVMIsAAllocaInst(value).is_null()
    {
        Some(PointerOrigins {
            roots: BTreeSet::from([key]),
            nullable: false,
        })
    } else if !LLVMIsAConstantExpr(value).is_null() {
        match LLVMGetConstOpcode(value) {
            LLVMOpcode::LLVMGetElementPtr
            | LLVMOpcode::LLVMBitCast
            | LLVMOpcode::LLVMAddrSpaceCast => pointer_origins(
                LLVMGetOperand(value, 0),
                visiting_values,
                visiting_slots,
                memo,
            ),
            LLVMOpcode::LLVMSelect => {
                let mut merged = PointerOrigins::default();
                for index in 1..LLVMGetNumOperands(value) {
                    merged.merge(pointer_origins(
                        LLVMGetOperand(value, index as u32),
                        visiting_values,
                        visiting_slots,
                        memo,
                    )?);
                }
                Some(merged)
            }
            _ => None,
        }
    } else if !LLVMIsAInstruction(value).is_null() {
        match LLVMGetInstructionOpcode(value) {
            LLVMOpcode::LLVMGetElementPtr => pointer_origins(
                LLVMGetOperand(value, 0),
                visiting_values,
                visiting_slots,
                memo,
            ),
            LLVMOpcode::LLVMBitCast | LLVMOpcode::LLVMAddrSpaceCast => pointer_origins(
                LLVMGetOperand(value, 0),
                visiting_values,
                visiting_slots,
                memo,
            ),
            LLVMOpcode::LLVMSelect | LLVMOpcode::LLVMPHI => {
                let start = usize::from(LLVMGetInstructionOpcode(value) == LLVMOpcode::LLVMSelect);
                let mut merged = PointerOrigins::default();
                for index in start..LLVMGetNumOperands(value) as usize {
                    merged.merge(pointer_origins(
                        LLVMGetOperand(value, index as u32),
                        visiting_values,
                        visiting_slots,
                        memo,
                    )?);
                }
                Some(merged)
            }
            LLVMOpcode::LLVMLoad => local_pointer_slot_origins(
                LLVMGetOperand(value, 0),
                visiting_values,
                visiting_slots,
                memo,
            ),
            LLVMOpcode::LLVMCall => direct_symbol_name(LLVMGetCalledValue(value))
                .and_then(|callee| external_return_alias_arg(&callee))
                .filter(|&index| index < LLVMGetNumArgOperands(value) as usize)
                .and_then(|index| {
                    pointer_origins(
                        LLVMGetOperand(value, index as u32),
                        visiting_values,
                        visiting_slots,
                        memo,
                    )
                }),
            _ => None,
        }
    } else {
        None
    };

    visiting_values.remove(&key);
    memo.insert(key, result.clone());
    result
}

/// Enumerate the complete contents of a direct local pointer spill. Any address use other than a
/// direct load/store or a debug/lifetime intrinsic makes the slot unsuitable for this proof.
unsafe fn local_pointer_slot_origins(
    slot: LLVMValueRef,
    visiting_values: &mut BTreeSet<usize>,
    visiting_slots: &mut BTreeSet<usize>,
    memo: &mut BTreeMap<usize, Option<PointerOrigins>>,
) -> Option<PointerOrigins> {
    let slot = strip_pointer_casts(slot);
    if LLVMIsAAllocaInst(slot).is_null()
        || LLVMGetTypeKind(LLVMGetAllocatedType(slot)) != LLVMTypeKind::LLVMPointerTypeKind
    {
        return None;
    }

    let slot_key = slot as usize;
    if !visiting_slots.insert(slot_key) {
        // A GEP-and-store update of a local pointer variable preserves the variable's existing
        // provenance. Treat the backedge as contributing no new root; a real initialization must
        // still be found elsewhere or the final singleton-root check will fail.
        return Some(PointerOrigins::default());
    }

    let mut merged = PointerOrigins::default();
    let mut saw_store = false;
    let mut usage = LLVMGetFirstUse(slot);
    while !usage.is_null() {
        let user = LLVMGetUser(usage);
        if user.is_null() || LLVMIsAInstruction(user).is_null() {
            visiting_slots.remove(&slot_key);
            return None;
        }
        match LLVMGetInstructionOpcode(user) {
            LLVMOpcode::LLVMLoad if LLVMGetOperand(user, 0) == slot => {}
            LLVMOpcode::LLVMStore if LLVMGetOperand(user, 1) == slot => {
                let Some(origins) = pointer_origins(
                    LLVMGetOperand(user, 0),
                    visiting_values,
                    visiting_slots,
                    memo,
                ) else {
                    visiting_slots.remove(&slot_key);
                    return None;
                };
                merged.merge(origins);
                saw_store = true;
            }
            LLVMOpcode::LLVMCall if benign_slot_intrinsic(user, slot) => {}
            _ => {
                visiting_slots.remove(&slot_key);
                return None;
            }
        }
        usage = LLVMGetNextUse(usage);
    }
    visiting_slots.remove(&slot_key);
    saw_store.then_some(merged)
}

unsafe fn benign_slot_intrinsic(user: LLVMValueRef, value: LLVMValueRef) -> bool {
    direct_symbol_name(LLVMGetCalledValue(user)).is_some_and(|callee| {
        (callee.starts_with("llvm.dbg.") || callee.starts_with("llvm.lifetime."))
            && (0..LLVMGetNumArgOperands(user)).any(|index| LLVMGetOperand(user, index) == value)
    })
}

/// Proves the Clang-style lowering of a relocation-invariant pointer difference:
///
/// ```text
/// lhs.i = ptrtoint lhs
/// rhs.i = ptrtoint rhs
/// delta = sub lhs.i, rhs.i
/// ```
///
/// Each converted value must be used only by the paired subtraction, and both source pointers must
/// have exactly one common non-null structural root. Nullable local-spill initializers do not add a
/// second root: on defined source-level executions of pointer subtraction both operands designate
/// the common array object. Once the raw addresses cancel, every downstream integer use observes a
/// relocation-invariant value, so unlike raw-address flow it need not be locally confined.
unsafe fn has_common_provenance_pointer_difference_uses(value: LLVMValueRef) -> bool {
    unsafe fn is_ptrtoint(value: LLVMValueRef) -> bool {
        (!LLVMIsAInstruction(value).is_null()
            && LLVMGetInstructionOpcode(value) == LLVMOpcode::LLVMPtrToInt)
            || (!LLVMIsAConstantExpr(value).is_null()
                && LLVMGetConstOpcode(value) == LLVMOpcode::LLVMPtrToInt)
    }

    let mut usage = LLVMGetFirstUse(value);
    let mut saw_difference = false;
    while !usage.is_null() {
        let difference = LLVMGetUser(usage);
        if difference.is_null()
            || LLVMIsAInstruction(difference).is_null()
            || LLVMGetInstructionOpcode(difference) != LLVMOpcode::LLVMSub
        {
            return false;
        }
        let lhs = LLVMGetOperand(difference, 0);
        let rhs = LLVMGetOperand(difference, 1);
        if (lhs != value && rhs != value)
            || !is_ptrtoint(lhs)
            || !is_ptrtoint(rhs)
            || LLVMTypeOf(lhs) != LLVMTypeOf(rhs)
        {
            return false;
        }
        for converted in [lhs, rhs]
            .into_iter()
            .filter(|converted| !LLVMIsAInstruction(*converted).is_null())
        {
            let converted_use = LLVMGetFirstUse(converted);
            if converted_use.is_null()
                || LLVMGetUser(converted_use) != difference
                || !LLVMGetNextUse(converted_use).is_null()
            {
                return false;
            }
        }

        let lhs_pointer = LLVMGetOperand(lhs, 0);
        let rhs_pointer = LLVMGetOperand(rhs, 0);
        let Some(lhs_origins) = pointer_origins(
            lhs_pointer,
            &mut BTreeSet::new(),
            &mut BTreeSet::new(),
            &mut BTreeMap::new(),
        ) else {
            return false;
        };
        let Some(rhs_origins) = pointer_origins(
            rhs_pointer,
            &mut BTreeSet::new(),
            &mut BTreeSet::new(),
            &mut BTreeMap::new(),
        ) else {
            return false;
        };
        if !lhs_origins.one_common_root(&rhs_origins) {
            return false;
        }

        saw_difference = true;
        usage = LLVMGetNextUse(usage);
    }
    saw_difference
}
