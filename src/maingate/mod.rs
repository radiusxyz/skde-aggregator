#![deny(missing_debug_implementations)]
// #![deny(missing_docs)]

#[macro_use]
///
pub(crate) mod instructions;
mod main_gate;
mod range;

use halo2_proofs::circuit::AssignedCell;
pub use instructions::{CombinationOptionCommon, MainGateInstructions, Term};
pub use main_gate::*;
pub use range::*;

/// AssignedValue
pub type AssignedValue<F> = AssignedCell<F, F>;
/// AssignedCondition
pub type AssignedCondition<F> = AssignedCell<F, F>;
