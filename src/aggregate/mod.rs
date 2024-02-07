pub mod chip;
pub use chip::*;
pub mod instructions;
use halo2wrong::halo2::circuit::Value;
pub use instructions::*;

use ff::{Field, PrimeField};

use crate::big_integer::*;

pub const MAX_SEQUENCER_NUMBER: usize = 20;
pub const BITS_LEN: usize = 2048; // n's bit length
pub const LIMB_WIDTH: usize = 64;
pub const LIMB_COUNT: usize = BITS_LEN / LIMB_WIDTH;

/// Aggregate extraction key that is about to be assigned.
#[derive(Clone, Debug)]
pub struct AggregateExtractionKey<F: Field> {
    pub u: UnassignedInteger<F>,
    pub v: UnassignedInteger<F>,
    pub y: UnassignedInteger<F>,
    pub w: UnassignedInteger<F>,
}

impl<F: PrimeField> AggregateExtractionKey<F> {
    /// Creates new [`AggregateExtractionKey`] from `u, v, y, w`.
    ///
    /// # Arguments
    /// * u - a parameter `u`.
    /// * v - a parameter `v`.
    /// * y - a parameter `y`.
    /// * w - a parameter `w`.
    ///
    /// # Return values
    /// Returns new [`AggregateExtractionKey`].
    pub fn new(
        u: UnassignedInteger<F>,
        v: UnassignedInteger<F>,
        y: UnassignedInteger<F>,
        w: UnassignedInteger<F>,
    ) -> Self {
        Self { u, v, y, w }
    }

    pub fn without_witness(num_limbs: usize) -> Self {
        let u = UnassignedInteger {
            value: Value::unknown(),
            num_limbs,
        };
        let v = UnassignedInteger {
            value: Value::unknown(),
            num_limbs,
        };
        let y = UnassignedInteger {
            value: Value::unknown(),
            num_limbs,
        };
        let w = UnassignedInteger {
            value: Value::unknown(),
            num_limbs,
        };
        Self { u, v, y, w }
    }
}

/// An assigned Aggregate extraction key.
#[derive(Clone, Debug)]
pub struct AssignedExtractionKey<F: PrimeField> {
    pub u: AssignedInteger<F, Fresh>,
    pub v: AssignedInteger<F, Fresh>,
    pub y: AssignedInteger<F, Fresh>,
    pub w: AssignedInteger<F, Fresh>,
}

impl<F: PrimeField> AssignedExtractionKey<F> {
    /// Creates new [`AssignedExtractionKey`] from assigned `u,v,y,w`.
    ///
    /// # Arguments
    /// * u - an assigned parameter `u`.
    /// * v - an assigned parameter `v`.
    /// * y - an assigned parameter `y`.
    /// * w - an assigned parameter `uw`.
    ///
    /// # Return values
    /// Returns new [`AssignedExtractionKey`].
    pub fn new(
        u: AssignedInteger<F, Fresh>,
        v: AssignedInteger<F, Fresh>,
        y: AssignedInteger<F, Fresh>,
        w: AssignedInteger<F, Fresh>,
    ) -> Self {
        Self { u, v, y, w }
    }
}

/// Aggregate public key that is about to be assigned.
#[derive(Clone, Debug)]
pub struct AggregatePublicParams<F: PrimeField> {
    /// a modulus parameter
    pub n: UnassignedInteger<F>,
    pub n_square: UnassignedInteger<F>,
}

impl<F: PrimeField> AggregatePublicParams<F> {
    /// Creates new [`AggregatePublicParams`] from `n`.
    ///
    /// # Arguments
    /// * n - an integer of `n`.
    ///
    /// # Return values
    /// Returns new [`AggregatePublicParams`].
    pub fn new(n: UnassignedInteger<F>, n_square: UnassignedInteger<F>) -> Self {
        Self { n, n_square }
    }

    pub fn without_witness(num_limbs: usize) -> Self {
        let n = UnassignedInteger {
            value: Value::unknown(),
            num_limbs,
        };
        let num_limb2 = num_limbs * 2;
        let n_square = UnassignedInteger {
            value: Value::unknown(),
            num_limbs: num_limb2,
        };
        Self { n, n_square }
    }
}

/// An assigned Aggregate public key.
#[derive(Clone, Debug)]
pub struct AssignedAggregatePublicParams<F: PrimeField> {
    /// a modulus parameter
    pub n: AssignedInteger<F, Fresh>,
    pub n_square: AssignedInteger<F, Fresh>,
}

impl<F: PrimeField> AssignedAggregatePublicParams<F> {
    /// Creates new [`AssignedAggregatePublicParams`] from assigned `n`.
    ///
    /// # Arguments
    /// * n - an assigned integer of `n`.
    ///
    /// # Return values
    /// Returns new [`AssignedAggregatePublicParams`].
    pub fn new(n: AssignedInteger<F, Fresh>, n_square: AssignedInteger<F, Fresh>) -> Self {
        Self { n, n_square }
    }
}

/// Aggregate public key that is about to be assigned.
#[derive(Clone, Debug)]
pub struct AggregatePartialKeys<F: PrimeField> {
    /// a modulus parameter
    pub partial_keys: Vec<AggregateExtractionKey<F>>,
}

impl<F: PrimeField> AggregatePartialKeys<F> {
    /// Creates new [`AggregatePartialKeys`] from `n`.
    ///
    /// # Arguments
    /// * partial_keys - a vector of `extraction keys`.
    ///
    /// # Return values
    /// Returns new [`AggregatePartialKeys`].
    pub fn new(partial_keys: Vec<AggregateExtractionKey<F>>) -> Self {
        Self { partial_keys }
    }

    pub fn without_witness(num_limbs: usize) -> Self {
        let mut partial_keys = vec![];
        for _ in 0..MAX_SEQUENCER_NUMBER {
            partial_keys.push(AggregateExtractionKey::without_witness(num_limbs));
        }
        Self { partial_keys }
    }
}

/// An assigned Aggregate public key.
#[derive(Clone, Debug)]
pub struct AssignedAggregatePartialKeys<F: PrimeField> {
    pub partial_keys: Vec<AssignedExtractionKey<F>>,
}

impl<F: PrimeField> AssignedAggregatePartialKeys<F> {
    /// Creates new [`AssignedAggregatePartialKeys`] from assigned `n`.
    ///
    /// # Arguments
    /// * partial_keys - an assigned vector of `extraction keys`.
    ///
    /// # Return values
    /// Returns new [`AssignedAggregatePartialKeys`].
    pub fn new(partial_keys: Vec<AssignedExtractionKey<F>>) -> Self {
        Self { partial_keys }
    }
}
