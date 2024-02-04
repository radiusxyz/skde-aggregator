use crate::big_integer::{BigIntChip, BigIntConfig, BigIntInstructions};
use crate::{
    AggregateExtractionKey, AggregateInstructions, AggregatePublicParams,
    AssignedAggregateExtractionKey, AssignedAggregatePartialKeys, AssignedAggregatePublicParams,
};
use halo2wrong::halo2::plonk::Error;
use maingate::{MainGate, RangeChip, RegionCtx};

use ff::PrimeField;
use num_bigint::BigUint;

use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct ExtractionKey {
    pub u: BigUint,
    pub v: BigUint,
    pub y: BigUint,
    pub w: BigUint,
}

use super::MAX_SEQUENCER_NUMBER;

/// Configuration for [`BigIntChip`].
#[derive(Clone, Debug)]
pub struct AggregateConfig {
    /// Configuration for [`BigIntChip`].
    pub bigint_config: BigIntConfig,
    pub bigint_square_config: BigIntConfig,
    // instance: Column<Instance>,
}

impl AggregateConfig {
    /// Creates new [`AggregateConfig`] from [`BigIntConfig`].
    ///
    /// # Arguments
    /// * bigint_config - a configuration for [`BigIntChip`].
    ///
    /// # Return values
    /// Returns new [`AggregateConfig`].
    pub fn new(bigint_config: BigIntConfig, bigint_square_config: BigIntConfig) -> Self {
        Self {
            bigint_config,
            bigint_square_config,
        }
    }
}

/// Chip for [`AggregateInstructions`].
#[derive(Debug, Clone)]
pub struct AggregateChip<F: PrimeField> {
    config: AggregateConfig,
    bits_len: usize,
    _f: PhantomData<F>,
}

impl<F: PrimeField> AggregateInstructions<F> for AggregateChip<F> {
    /// Assigns a [`AssignedAggregatePublicKey`].
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `public_key` - a Aggregate public key to assign.
    ///
    /// # Return values
    /// Returns a new [`AssignedAggregatePublicKey`].
    fn assign_extraction_key(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        extraction_key: AggregateExtractionKey<F>,
    ) -> Result<AssignedAggregateExtractionKey<F>, Error> {
        let bigint_chip = self.bigint_chip();
        let bigint_square_chip: BigIntChip<F> = self.bigint_square_chip();

        let u = bigint_chip.assign_integer(ctx, extraction_key.u)?;
        let v = bigint_square_chip.assign_integer(ctx, extraction_key.v)?;
        let y = bigint_chip.assign_integer(ctx, extraction_key.y)?;
        let w = bigint_square_chip.assign_integer(ctx, extraction_key.w)?;
        Ok(AssignedAggregateExtractionKey::new(u, v, y, w))
    }

    /// Assigns a [`AssignedAggregatePublicParams`].
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `public_key` - a Aggregate public key to assign.
    ///
    /// # Return values
    /// Returns a new [`AssignedAggregatePublicParams`].
    fn assign_public_params(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        public_params: AggregatePublicParams<F>,
    ) -> Result<AssignedAggregatePublicParams<F>, Error> {
        let bigint_chip = self.bigint_chip();
        let bigint_square_chip = self.bigint_square_chip();
        // let bigint_square_chip = self.bigint_square_chip();
        let n = bigint_chip.assign_integer(ctx, public_params.n)?;
        let n_square = bigint_square_chip.assign_integer(ctx, public_params.n_square)?;
        Ok(AssignedAggregatePublicParams::new(n, n_square))
    }

    /// Given a base `x`, a Aggregate public key (e,n), performs the modular power `x^e mod n`.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `partial_keys` - a vector of input partial keys.
    /// * `aggregated_key` - an aggregated key for output.
    /// * `public_params` - an assigned Aggregate public params.
    ///
    /// # Return values
    /// Returns the modular power result `x^e mod n` as [`AssignedInteger<F, Fresh>`].
    fn aggregate(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        partial_keys: &AssignedAggregatePartialKeys<F>,
        public_params: &AssignedAggregatePublicParams<F>,
    ) -> Result<AssignedAggregateExtractionKey<F>, Error> {
        let bigint_chip = self.bigint_chip();
        let bigint_square_chip = self.bigint_square_chip();
        for each_key in partial_keys.partial_keys.iter() {
            bigint_chip.assert_in_field(ctx, &each_key.u, &public_params.n)?;
            bigint_square_chip.assert_in_field(ctx, &each_key.v, &public_params.n_square)?;
            bigint_chip.assert_in_field(ctx, &each_key.y, &public_params.n)?;
            bigint_square_chip.assert_in_field(ctx, &each_key.w, &public_params.n_square)?;
        }
        let mut u = partial_keys.partial_keys[0].u.clone();
        let mut v = partial_keys.partial_keys[0].v.clone();
        let mut y = partial_keys.partial_keys[0].y.clone();
        let mut w = partial_keys.partial_keys[0].w.clone();

        for i in 1..MAX_SEQUENCER_NUMBER {
            u = bigint_chip.mul_mod(ctx, &u, &partial_keys.partial_keys[i].u, &public_params.n)?;
            v = bigint_square_chip.mul_mod(
                ctx,
                &v,
                &partial_keys.partial_keys[i].v,
                &public_params.n_square,
            )?;
            y = bigint_chip.mul_mod(ctx, &y, &partial_keys.partial_keys[i].y, &public_params.n)?;
            w = bigint_square_chip.mul_mod(
                ctx,
                &w,
                &partial_keys.partial_keys[i].w,
                &public_params.n_square,
            )?;
        }

        Ok(AssignedAggregateExtractionKey::new(
            u.clone(),
            v.clone(),
            y.clone(),
            w.clone(),
        ))
    }
}

impl<F: PrimeField> AggregateChip<F> {
    pub const LIMB_WIDTH: usize = 64;

    /// Create a new [`AggregateChip`] from the configuration and parameters.
    ///
    /// # Arguments
    /// * config - a configuration for [`AggregateChip`].
    /// * bits_len - the default bit length of [`Fresh`] type integers in this chip.
    /// * exp_limb_bits - the width of each limb when the exponent is decomposed.
    ///
    /// # Return values
    /// Returns a new [`AggregateChip`]
    pub fn new(config: AggregateConfig, bits_len: usize) -> Self {
        AggregateChip {
            config,
            bits_len,
            _f: PhantomData,
        }
    }

    /// Getter for [`BigIntChip`].
    pub fn bigint_chip(&self) -> BigIntChip<F> {
        BigIntChip::<F>::new(
            self.config.bigint_config.clone(),
            Self::LIMB_WIDTH,
            self.bits_len,
        )
    }

    /// Getter for [`BigIntSquareChip`].
    pub fn bigint_square_chip(&self) -> BigIntChip<F> {
        BigIntChip::<F>::new(
            self.config.bigint_square_config.clone(),
            Self::LIMB_WIDTH,
            self.bits_len * 2,
        )
    }

    /// Getter for [`RangeChip`].
    pub fn range_chip(&self) -> RangeChip<F> {
        self.bigint_chip().range_chip()
    }

    /// Getter for [`MainGate`].
    pub fn main_gate(&self) -> MainGate<F> {
        self.bigint_chip().main_gate()
    }

    /// Getter for [`RangeChip`].
    pub fn square_range_chip(&self) -> RangeChip<F> {
        self.bigint_square_chip().range_chip()
    }

    /// Getter for [`MainGate`].
    pub fn square_main_gate(&self) -> MainGate<F> {
        self.bigint_square_chip().main_gate()
    }

    /// Returns the bit length parameters necessary to configure the [`RangeChip`].
    ///
    /// # Arguments
    /// * num_limbs - the default number of limbs of [`Fresh`] integers.
    ///
    /// # Return values
    /// Returns a vector of composition bit lengthes (`composition_bit_lens`) and a vector of overflow bit lengthes (`overflow_bit_lens`), which are necessary for [`RangeConfig`].
    pub fn compute_range_lens(num_limbs: usize) -> (Vec<usize>, Vec<usize>) {
        let (mut composition_bit_lens, overflow_bit_lens) =
            BigIntChip::<F>::compute_range_lens(Self::LIMB_WIDTH, num_limbs);
        composition_bit_lens.push(32 / BigIntChip::<F>::NUM_LOOKUP_LIMBS);
        (composition_bit_lens, overflow_bit_lens)
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use ff::FromUniformBytes;
    use halo2wrong::halo2::dev::MockProver;
    use halo2wrong::halo2::{
        // circuit::floor_planner,
        circuit::SimpleFloorPlanner,
        plonk::{Circuit, ConstraintSystem},
    };
    use maingate::{decompose_big, RangeInstructions};
    use num_bigint::BigUint;
    use num_bigint::RandomBits;
    use rand::{thread_rng, Rng};

    macro_rules! impl_aggregate_test_circuit{
        ($circuit_name:ident, $test_fn_name:ident, $bits_len:expr, $should_be_error:expr, $( $synth:tt )*) => {
            struct $circuit_name<F: PrimeField> {
                partial_keys: Vec<ExtractionKey>,
                aggregated_key: ExtractionKey,
                n: BigUint,
                n_square: BigUint,
                _f: PhantomData<F>
            }

            impl<F: PrimeField> $circuit_name<F> {
                const BITS_LEN:usize = $bits_len; // n's bit length
                const LIMB_WIDTH:usize = AggregateChip::<F>::LIMB_WIDTH;
                fn aggregate_chip(&self, config: AggregateConfig) -> AggregateChip<F> {
                    AggregateChip::new(config, Self::BITS_LEN)
                }
            }

            impl<F: PrimeField> Circuit<F> for $circuit_name<F> {
                type Config = AggregateConfig;
                type FloorPlanner = SimpleFloorPlanner;

                fn without_witnesses(&self) -> Self {
                    unimplemented!();
                }

                fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                    let main_gate_config = MainGate::<F>::configure(meta);
                    let (composition_bit_lens, overflow_bit_lens) =
                        AggregateChip::<F>::compute_range_lens(
                            Self::BITS_LEN / Self::LIMB_WIDTH,
                        );
                    let range_config = RangeChip::<F>::configure(
                        meta,
                        &main_gate_config,
                        composition_bit_lens,
                        overflow_bit_lens,
                    );
                    let (square_composition_bit_lens, square_overflow_bit_lens) =
                        AggregateChip::<F>::compute_range_lens(
                            Self::BITS_LEN * 2 / Self::LIMB_WIDTH,
                        );
                    let square_range_config = RangeChip::<F>::configure(
                        meta,
                        &main_gate_config,
                        square_composition_bit_lens,
                        square_overflow_bit_lens,
                    );
                    let bigint_config = BigIntConfig::new(range_config.clone(), main_gate_config.clone());
                    let bigint_square_config = BigIntConfig::new(square_range_config.clone(), main_gate_config.clone());

                    //TODO add instance to check agg key
                    // let instance = meta.instance_column();
                    // meta.enable_equality(instance);

                    Self::Config{
                        bigint_config,
                        bigint_square_config,
                        // instance
                    }
                }

                $( $synth )*

            }

            #[test]
            fn $test_fn_name() {
                fn run<F: FromUniformBytes<64> + Ord>() {
                    let mut rng = thread_rng();
                    let bits_len = $circuit_name::<F>::BITS_LEN as u64;
                    let mut n = BigUint::default();
                    while n.bits() != bits_len {
                        n = rng.sample(RandomBits::new(bits_len));
                    }
                    let n_square = &n * &n;

                    let mut partial_keys = vec![];

                    let mut aggregated_key = ExtractionKey{
                        u: BigUint::from(1usize), v: BigUint::from(1usize), y: BigUint::from(1usize), w: BigUint::from(1usize),
                    };

                    for _ in 0..MAX_SEQUENCER_NUMBER{
                        let u = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;
                        let v = rng.sample::<BigUint, _>(RandomBits::new(bits_len*2)) % &n_square;
                        let y = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;
                        let w = rng.sample::<BigUint, _>(RandomBits::new(bits_len*2)) % &n_square;

                        partial_keys.push(ExtractionKey{u: u.clone(), v: v.clone(), y: y.clone(), w: w.clone()});

                        aggregated_key.u = aggregated_key.u * &u % &n;
                        aggregated_key.v = aggregated_key.v * &v % &n_square;
                        aggregated_key.y = aggregated_key.y * &y % &n;
                        aggregated_key.w = aggregated_key.w * &w % &n_square;
                    }

                    let circuit = $circuit_name::<F> {
                        partial_keys,
                        aggregated_key,
                        n,
                        n_square,
                        _f: PhantomData
                    };

                    let public_inputs = vec![vec![]];
                    let k = 20;
                    let prover = match MockProver::run(k, &circuit, public_inputs) {
                        Ok(prover) => prover,
                        Err(e) => panic!("{:#?}", e)
                    };
                    assert_eq!(prover.verify().is_err(), $should_be_error);
                }

                use halo2wrong::curves::bn256::Fq as BnFq;
                // use halo2wrong::curves::pasta::{Fp as PastaFp, Fq as PastaFq};
                run::<BnFq>();
                // run::<PastaFp>();
                // run::<PastaFq>();
            }
        };
    }

    use crate::UnassignedInteger;

    impl_aggregate_test_circuit!(
        TestAggregate2048Circuit,
        test_aggregate_2048_circuit,
        2048, // this is bit length of n. n^2's length is the double of n's.
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let aggregate_chip = self.aggregate_chip(config);
            let bigint_chip = aggregate_chip.bigint_chip();
            let bigint_square_chip = aggregate_chip.bigint_square_chip();
            let limb_width = Self::LIMB_WIDTH;
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            layouter.assign_region(
                || "aggregate test with 2048 bits RSA parameter",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, limb_width);
                    let n_unassigned = UnassignedInteger::from(n_limbs);

                    let n_square_limbs =
                        decompose_big::<F>(self.n_square.clone(), num_limbs * 2, limb_width);
                    let n_square_unassigned = UnassignedInteger::from(n_square_limbs);

                    let mut partial_keys_assigned = vec![];
                    for i in 0..MAX_SEQUENCER_NUMBER {
                        let u_limbs = decompose_big::<F>(
                            self.partial_keys[i].u.clone(),
                            num_limbs,
                            limb_width,
                        );
                        let u_unassigned = UnassignedInteger::from(u_limbs);

                        let v_limbs = decompose_big::<F>(
                            self.partial_keys[i].v.clone(),
                            num_limbs * 2,
                            limb_width,
                        );
                        let v_unassigned = UnassignedInteger::from(v_limbs);

                        let y_limbs = decompose_big::<F>(
                            self.partial_keys[i].y.clone(),
                            num_limbs,
                            limb_width,
                        );
                        let y_unassigned = UnassignedInteger::from(y_limbs);

                        let w_limbs = decompose_big::<F>(
                            self.partial_keys[i].w.clone(),
                            num_limbs * 2,
                            limb_width,
                        );
                        let w_unassigned = UnassignedInteger::from(w_limbs);
                        let extraction_key_unassgined = AggregateExtractionKey::new(
                            u_unassigned,
                            v_unassigned,
                            y_unassigned,
                            w_unassigned,
                        );
                        partial_keys_assigned.push(
                            aggregate_chip.assign_extraction_key(ctx, extraction_key_unassgined)?,
                        );
                    }
                    let partial_keys = AssignedAggregatePartialKeys::new(partial_keys_assigned);

                    let agg_u_limbs =
                        decompose_big::<F>(self.aggregated_key.u.clone(), num_limbs, limb_width);
                    let agg_v_limb = decompose_big::<F>(
                        self.aggregated_key.v.clone(),
                        num_limbs * 2,
                        limb_width,
                    );
                    let agg_y_limbs =
                        decompose_big::<F>(self.aggregated_key.y.clone(), num_limbs, limb_width);
                    let agg_w_limb = decompose_big::<F>(
                        self.aggregated_key.w.clone(),
                        num_limbs * 2,
                        limb_width,
                    );
                    let agg_u_unassigned = UnassignedInteger::from(agg_u_limbs);
                    let agg_v_unassigned = UnassignedInteger::from(agg_v_limb);
                    let agg_y_unassigned = UnassignedInteger::from(agg_y_limbs);
                    let agg_w_unassigned = UnassignedInteger::from(agg_w_limb);
                    let agg_key_unassigned = AggregateExtractionKey::new(
                        agg_u_unassigned,
                        agg_v_unassigned,
                        agg_y_unassigned,
                        agg_w_unassigned,
                    );
                    let agg_key_assigned =
                        aggregate_chip.assign_extraction_key(ctx, agg_key_unassigned)?;
                    // let agg_key = AssignedAggregateExtractionKey::new(
                    //     agg_key_assigned.u.clone(),
                    //     agg_key_assigned.v.clone(),
                    //     agg_key_assigned.y.clone(),
                    //     agg_key_assigned.w.clone(),
                    // );

                    let public_params_unassigned = AggregatePublicParams::new(
                        n_unassigned.clone(),
                        n_square_unassigned.clone(),
                    );
                    let public_params =
                        aggregate_chip.assign_public_params(ctx, public_params_unassigned)?;
                    let valid_agg_key = aggregate_chip.aggregate(
                        ctx,
                        &partial_keys.clone(),
                        &public_params.clone(),
                    )?;

                    // TODO add instance to check agg key
                    // let u_cells = aggregated_extraction_key
                    //     .u
                    //     .limbs()
                    //     .into_iter()
                    //     .map(|v| v.assigned_val().cell())
                    //     .collect::<Vec<Cell>>();
                    // Ok(u_cells)

                    bigint_chip.assert_equal_fresh(ctx, &valid_agg_key.u, &agg_key_assigned.u)?;
                    bigint_square_chip.assert_equal_fresh(
                        ctx,
                        &valid_agg_key.v,
                        &agg_key_assigned.v,
                    )?;
                    bigint_chip.assert_equal_fresh(ctx, &valid_agg_key.y, &agg_key_assigned.y)?;
                    bigint_square_chip.assert_equal_fresh(
                        ctx,
                        &valid_agg_key.w,
                        &agg_key_assigned.w,
                    )?;

                    Ok(())
                },
            )?;
            let range_chip = bigint_chip.range_chip();
            let range_square_chip = bigint_square_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            range_square_chip.load_table(&mut layouter)?;

            // TODO add instance to check agg key
            // for (i, cell) in agg_extraction_key.into_iter().enumerate() {
            //     layouter.constrain_instance(cell, config.instance, i);
            // }
            Ok(())
        }
    );
}
