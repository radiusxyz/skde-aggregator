pub mod chip;
pub use chip::*;
pub mod instructions;
use halo2_proofs::circuit::Value;
pub use instructions::*;

use ff::{Field, PrimeField};
use num_bigint::BigUint;

use crate::big_integer::*;

pub const MAX_SEQUENCER_NUMBER: usize = 20;
pub const BITS_LEN: usize = 2048; // n's bit length
pub const LIMB_WIDTH: usize = 64;
pub const LIMB_COUNT: usize = BITS_LEN / LIMB_WIDTH;

// p * q = 109108784166676529682340577929498188950239585527883687884827626040722072371127456712391033422811328348170518576414206624244823392702116014678887602655605057984874271545556188865755301275371611259397284800785551682318694176857633188036311000733221068448165870969366710007572931433736793827320953175136545355129
pub const PRIME_P: &str = "8155133734070055735139271277173718200941522166153710213522626777763679009805792017274916613411023848268056376687809186180768200590914945958831360737612803";
pub const PRIME_Q: &str = "13379153270147861840625872456862185586039997603014979833900847304743997773803109864546170215161716700184487787472783869920830925415022501258643369350348243";
pub const GENERATOR: &str = "4";
pub const TIME_PARAM_T: u32 = 23; // delay time depends on: 2^TIME_PARMA_T

#[derive(Debug, Clone)]
pub struct ExtractionKey {
    pub u: BigUint,
    pub v: BigUint,
    pub y: BigUint,
    pub w: BigUint,
}

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
