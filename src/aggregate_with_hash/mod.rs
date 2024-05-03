pub mod chip;
pub use chip::*;
pub mod instructions;
use halo2wrong::halo2::circuit::Value;
pub use instructions::*;

use ff::PrimeField;

use crate::big_integer::*;

pub const MAX_SEQUENCER_NUMBER2: usize = 20;

/// AggregateWithHash extraction key that is about to be assigned.
#[derive(Clone, Debug)]
pub struct AggregateWithHashExtractionKey<F: PrimeField> {
    pub u: UnassignedInteger<F>,
    pub v: UnassignedInteger<F>,
    pub y: UnassignedInteger<F>,
    pub w: UnassignedInteger<F>,
}

impl<F: PrimeField> AggregateWithHashExtractionKey<F> {
    /// Creates new [`AggregateWithHashExtractionKey`] from `u, v, y, w`.
    ///
    /// # Arguments
    /// * u - a parameter `u`.
    /// * v - a parameter `v`.
    /// * y - a parameter `y`.
    /// * w - a parameter `w`.
    ///
    /// # Return values
    /// Returns new [`AggregateWithHashExtractionKey`].
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

/// An assigned AggregateWithHash extraction key.
#[derive(Clone, Debug)]
pub struct AssignedAggregateWithHashExtractionKey<F: PrimeField> {
    pub u: AssignedInteger<F, Fresh>,
    pub v: AssignedInteger<F, Fresh>,
    pub y: AssignedInteger<F, Fresh>,
    pub w: AssignedInteger<F, Fresh>,
}

impl<F: PrimeField> AssignedAggregateWithHashExtractionKey<F> {
    /// Creates new [`AssignedAggregateWithHashExtractionKey`] from assigned `u,v,y,w`.
    ///
    /// # Arguments
    /// * u - an assigned parameter `u`.
    /// * v - an assigned parameter `v`.
    /// * y - an assigned parameter `y`.
    /// * w - an assigned parameter `uw`.
    ///
    /// # Return values
    /// Returns new [`AssignedAggregateWithHashExtractionKey`].
    pub fn new(
        u: AssignedInteger<F, Fresh>,
        v: AssignedInteger<F, Fresh>,
        y: AssignedInteger<F, Fresh>,
        w: AssignedInteger<F, Fresh>,
    ) -> Self {
        Self { u, v, y, w }
    }
}

/// Public Parameters that is about to be assigned.
#[derive(Clone, Debug)]
pub struct AggregateWithHashPublicParams<F: PrimeField> {
    /// a modulus parameter
    pub n: UnassignedInteger<F>,
    pub n_square: UnassignedInteger<F>,
}

impl<F: PrimeField> AggregateWithHashPublicParams<F> {
    /// Creates new [`AggregateWithHashPublicParams`] from `n`.
    ///
    /// # Arguments
    /// * n - an integer of `n`.
    /// * n_square - an integer of `n^2`.
    ///
    /// # Return values
    /// Returns new [`AggregateWithHashPublicParams`].
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

/// Assigned AggregateWithHash public params.
#[derive(Clone, Debug)]
pub struct AssignedAggregateWithHashPublicParams<F: PrimeField> {
    /// modulus parameter
    pub n: AssignedInteger<F, Fresh>,
    pub n_square: AssignedInteger<F, Fresh>,
}

impl<F: PrimeField> AssignedAggregateWithHashPublicParams<F> {
    /// Creates new [`AssignedAggregateWithHashPublicParams`] from assigned `n`.
    ///
    /// # Arguments
    /// * n - an assigned integer of `n`.
    /// * n_square - an assigned integer of `n^2`.
    ///
    /// # Return values
    /// Returns new [`AssignedAggregateWithHashPublicParams`].
    pub fn new(n: AssignedInteger<F, Fresh>, n_square: AssignedInteger<F, Fresh>) -> Self {
        Self { n, n_square }
    }
}

/// AggregateWithHash partial keys that is about to be assigned.
#[derive(Clone, Debug)]
pub struct AggregateWithHashPartialKeys<F: PrimeField> {
    /// a modulus parameter
    pub partial_keys: Vec<AggregateWithHashExtractionKey<F>>,
}

impl<F: PrimeField> AggregateWithHashPartialKeys<F> {
    /// Creates new [`AggregateWithHashPartialKeys`] from `n`.
    ///
    /// # Arguments
    /// * partial_keys - a vector of `extraction keys`.
    ///
    /// # Return values
    /// Returns new [`AggregateWithHashPartialKeys`].
    pub fn new(partial_keys: Vec<AggregateWithHashExtractionKey<F>>) -> Self {
        Self { partial_keys }
    }

    pub fn without_witness(num_limbs: usize) -> Self {
        let mut partial_keys = vec![];
        for _ in 0..MAX_SEQUENCER_NUMBER2 {
            partial_keys.push(AggregateWithHashExtractionKey::without_witness(num_limbs));
        }
        Self { partial_keys }
    }
}

/// Assigned AggregateWithHash partial keys.
#[derive(Clone, Debug)]
pub struct AssignedAggregateWithHashPartialKeys<F: PrimeField> {
    pub partial_keys: Vec<AssignedAggregateWithHashExtractionKey<F>>,
}

impl<F: PrimeField> AssignedAggregateWithHashPartialKeys<F> {
    /// Creates new [`AssignedAggregateWithHashPartialKeys`] from assigned `n`.
    ///
    /// # Arguments
    /// * partial_keys - an assigned vector of `extraction keys`.
    ///
    /// # Return values
    /// Returns new [`AssignedAggregateWithHashPartialKeys`].
    pub fn new(partial_keys: Vec<AssignedAggregateWithHashExtractionKey<F>>) -> Self {
        Self { partial_keys }
    }
}