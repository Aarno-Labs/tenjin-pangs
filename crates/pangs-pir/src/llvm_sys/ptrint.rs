//! Use-sensitive validation for LLVM `ptrtoint` instructions.
//!
//! Integerizing a pointer is not itself evidence that the pointer representation escapes.  This
//! module proves two deliberately narrow classes of harmless uses:
//!
//! * a closed integer computation whose only terminal operation is a comparison or switch; and
//! * a paired subtraction of two pointer representations.
//!
//! The second class relies on the supported-program contract documented in `DESIGN_lite.md`:
//! paired subtraction represents source-level pointer difference, not an integer-encoded callback
//! reconstructed locally or across an unanalyzed boundary. LLVM IR cannot distinguish those
//! source idioms.

use std::collections::{BTreeMap, BTreeSet};

use llvm_sys::core::*;
use llvm_sys::prelude::*;
use llvm_sys::LLVMOpcode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PtrToIntUse {
    EscapingOrUnknown,
    ClosedComparison,
    PairedPointerDifference,
}

impl PtrToIntUse {
    pub(super) fn is_innocuous(self) -> bool {
        !matches!(self, Self::EscapingOrUnknown)
    }
}

/// Classify a conversion using only facts that are preserved in LLVM IR.  This is intentionally
/// independent of PIR lowering so all ptr/int policy remains in one place.
pub(super) unsafe fn classify(value: LLVMValueRef) -> PtrToIntUse {
    if has_paired_pointer_difference_uses(value) {
        PtrToIntUse::PairedPointerDifference
    } else if has_closed_comparison_uses(value) {
        PtrToIntUse::ClosedComparison
    } else {
        PtrToIntUse::EscapingOrUnknown
    }
}

/// Proves that a `ptrtoint` result remains inside the small integer domain whose only terminal
/// operation is `icmp` or `switch`. A switch is the optimized multi-way form of comparisons
/// against constants (notably Clang's null/TOMBSTONE hashmap checks); it observes the integer only
/// to select a control-flow successor. Unknown users fail closed. Cyclic phi graphs are accepted
/// only when every edge leaving the cycle eventually reaches a supported
/// comparison/arithmetic node.
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
                LLVMOpcode::LLVMICmp | LLVMOpcode::LLVMSwitch => true,
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

/// Recognizes the Clang-style shape used for pointer differences:
///
/// ```text
/// lhs.i = ptrtoint lhs
/// rhs.i = ptrtoint rhs
/// delta = sub lhs.i, rhs.i
/// ```
///
/// Each converted value must be used only by subtractions whose other operand is another
/// same-width `ptrtoint`. A conversion may be shared by several differences (for example
/// `end - line` and `loc - line`) as long as every use has that shape. Source provenance is
/// deliberately not recovered here; see the supported-program contract in `DESIGN_lite.md`.
unsafe fn has_paired_pointer_difference_uses(value: LLVMValueRef) -> bool {
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

        saw_difference = true;
        usage = LLVMGetNextUse(usage);
    }
    saw_difference
}
