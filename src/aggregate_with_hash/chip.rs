use crate::big_integer::{BigIntChip, BigIntConfig, BigIntInstructions};
use crate::hash::chip::HasherChip;
use crate::poseidon::chip::{FULL_ROUND, PARTIAL_ROUND};
use crate::poseidon::Poseidon;
use crate::{
    AggregateWithHashExtractionKey, AggregateWithHashInstructions, AggregateWithHashPublicParams,
    AssignedAggregateWithHashExtractionKey, AssignedAggregateWithHashPartialKeys,
    AssignedAggregateWithHashPublicParams, PoseidonChip, Spec,
};
use halo2wrong::halo2::circuit::AssignedCell;
use halo2wrong::halo2::plonk::{Column, Error, Instance};
use maingate::{MainGate, MainGateConfig, RangeChip, RegionCtx};

use ff::{FromUniformBytes, PrimeField};
use num_bigint::BigUint;

use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct ExtractionKey2 {
    pub u: BigUint,
    pub v: BigUint,
    pub y: BigUint,
    pub w: BigUint,
}

use super::MAX_SEQUENCER_NUMBER2;

/// Configuration for [`BigIntChip`].
#[derive(Clone, Debug)]
pub struct AggregateWithHashConfig {
    /// Configuration for [`BigIntChip`].
    pub bigint_config: BigIntConfig,
    pub bigint_square_config: BigIntConfig,
    pub hash_config: MainGateConfig,
}

impl AggregateWithHashConfig {
    /// Creates new [`AggregateWithHashConfig`] from [`BigIntConfig`].
    ///
    /// # Arguments
    /// * bigint_config - a configuration for [`BigIntChip`].
    ///
    /// # Return values
    /// Returns new [`AggregateWithHashConfig`].
    pub fn new(
        bigint_config: BigIntConfig,
        bigint_square_config: BigIntConfig,
        hash_config: MainGateConfig,
    ) -> Self {
        Self {
            bigint_config,
            bigint_square_config,
            hash_config,
        }
    }
}

/// Chip for [`AggregateWithHashInstructions`].
#[derive(Debug, Clone)]
pub struct AggregateWithHashChip<
    F: PrimeField + FromUniformBytes<64>,
    const T: usize,
    const RATE: usize,
> {
    config: AggregateWithHashConfig,
    bits_len: usize,
    _f: PhantomData<F>,
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize>
    AggregateWithHashInstructions<F> for AggregateWithHashChip<F, T, RATE>
{
    /// Assigns a [`AssignedAggregateWithHashPublicKey`].
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `extraction_key` - an extraction key to assign.
    ///
    /// # Return values
    /// Returns a new [`AssignedAggregateWithHashPublicKey`].
    fn assign_extraction_key(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        extraction_key: AggregateWithHashExtractionKey<F>,
    ) -> Result<AssignedAggregateWithHashExtractionKey<F>, Error> {
        let bigint_chip = self.bigint_chip();
        let bigint_square_chip: BigIntChip<F> = self.bigint_square_chip();

        let u = bigint_chip.assign_integer(ctx, extraction_key.u)?;
        let v = bigint_square_chip.assign_integer(ctx, extraction_key.v)?;
        let y = bigint_chip.assign_integer(ctx, extraction_key.y)?;
        let w = bigint_square_chip.assign_integer(ctx, extraction_key.w)?;
        Ok(AssignedAggregateWithHashExtractionKey::new(u, v, y, w))
    }

    /// Assigns a [`AssignedAggregateWithHashPublicParams`].
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `public_params` - public parameters to assign.
    ///
    /// # Return values
    /// Returns a new [`AssignedAggregateWithHashPublicParams`].
    fn assign_public_params(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        public_params: AggregateWithHashPublicParams<F>,
    ) -> Result<AssignedAggregateWithHashPublicParams<F>, Error> {
        let bigint_chip = self.bigint_chip();
        let bigint_square_chip = self.bigint_square_chip();
        let n = bigint_chip.assign_integer(ctx, public_params.n)?;
        let n_square = bigint_square_chip.assign_integer(ctx, public_params.n_square)?;
        Ok(AssignedAggregateWithHashPublicParams::new(n, n_square))
    }

    /// Given partial keys `Vec<(u,v,y,w)>`, a AggregateWithHash extraction key (u,v,y,w), performs the modular multiplication repeatedly.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `partial_keys` - a vector of input partial keys.
    /// * `public_params` - an assigned AggregateWithHash public params.
    ///
    /// # Return values
    /// Returns an aggregated key for output as [`AssignedAggregateWithHashExtractionKey<F>`].
    fn aggregate_with_hash(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        partial_keys: &AssignedAggregateWithHashPartialKeys<F>,
        public_params: &AssignedAggregateWithHashPublicParams<F>,
    ) -> Result<AssignedAggregateWithHashExtractionKey<F>, Error> {
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

        for i in 1..MAX_SEQUENCER_NUMBER2 {
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

        Ok(AssignedAggregateWithHashExtractionKey::new(
            u.clone(),
            v.clone(),
            y.clone(),
            w.clone(),
        ))
    }
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize>
    AggregateWithHashChip<F, T, RATE>
{
    pub const LIMB_WIDTH: usize = 64;

    /// Create a new [`AggregateWithHashChip`] from the configuration and parameters.
    ///
    /// # Arguments
    /// * config - a configuration for [`AggregateWithHashChip`].
    /// * bits_len - the default bit length of [`Fresh`] type integers in this chip.
    ///
    /// # Return values
    /// Returns a new [`AggregateWithHashChip`]
    pub fn new(config: AggregateWithHashConfig, bits_len: usize) -> Self {
        AggregateWithHashChip {
            config,
            bits_len,
            _f: PhantomData,
        }
    }

    pub fn new_bigint(config: BigIntConfig, bits_len: usize) -> BigIntChip<F> {
        BigIntChip::<F>::new(config, Self::LIMB_WIDTH, bits_len)
    }

    pub fn new_hash(
        ctx: &mut RegionCtx<'_, F>,
        spec: &Spec<F, T, RATE>,
        main_gate_config: &MainGateConfig,
    ) -> Result<HasherChip<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>, Error> {
        let pos_hash_chip = PoseidonChip::<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>::new_hash(
            ctx,
            spec,
            main_gate_config,
        )?;

        Ok(HasherChip {
            pose_chip: pos_hash_chip,
        })
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
    use halo2wrong::halo2::circuit::{AssignedCell, Chip};
    use halo2wrong::halo2::dev::MockProver;
    use halo2wrong::halo2::{
        circuit::SimpleFloorPlanner,
        plonk::{Circuit, ConstraintSystem},
    };
    use maingate::{big_to_fe, decompose_big, MainGateInstructions, RangeInstructions};
    use num_bigint::BigUint;
    use num_bigint::RandomBits;
    use rand::{thread_rng, Rng};

    macro_rules! impl_aggregate_with_hash_test_circuit{
        ($circuit_name:ident, $test_fn_name:ident, $bits_len:expr, $should_be_error:expr, $( $synth:tt )*) => {
            struct $circuit_name<F: PrimeField, const T: usize, const RATE: usize> {
                partial_keys: Vec<ExtractionKey2>,
                n: BigUint,
                // Poseidon Hash
                spec: Spec<F, T, RATE>,
                n_square: BigUint,
                _f: PhantomData<F>
            }

            impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize> $circuit_name<F, T, RATE> {
                const BITS_LEN:usize = $bits_len; // n's bit length
                const LIMB_WIDTH:usize = AggregateWithHashChip::<F, T, RATE>::LIMB_WIDTH;
                fn aggregate_with_hash_chip(&self, config: AggregateWithHashConfig) -> AggregateWithHashChip<F, T, RATE> {
                    AggregateWithHashChip::new(config, Self::BITS_LEN)
                }
            }

            impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize> Circuit<F> for $circuit_name<F, T, RATE> {
                type Config = AggregateWithHashConfig;
                type FloorPlanner = SimpleFloorPlanner;

                fn without_witnesses(&self) -> Self {
                    unimplemented!();
                }

                fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                    let main_gate_config = MainGate::<F>::configure(meta);
                    let (composition_bit_lens, overflow_bit_lens) =
                        AggregateWithHashChip::<F, T, RATE>::compute_range_lens(
                            Self::BITS_LEN / Self::LIMB_WIDTH,
                        );
                    let range_config = RangeChip::<F>::configure(
                        meta,
                        &main_gate_config,
                        composition_bit_lens,
                        overflow_bit_lens,
                    );
                    let (square_composition_bit_lens, square_overflow_bit_lens) =
                        AggregateWithHashChip::<F, T, RATE>::compute_range_lens(
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

                    let hash_config = main_gate_config.clone();


                    Self::Config{
                        bigint_config,
                        bigint_square_config,
                        hash_config,
                    }
                }

                $( $synth )*

            }

            #[test]
            fn $test_fn_name() {
                fn run<F: PrimeField + FromUniformBytes<64> + Ord, const T: usize, const RATE: usize>() {
                    let mut rng = thread_rng();
                    let bits_len = $circuit_name::<F, T, RATE>::BITS_LEN as u64;
                    let mut n = BigUint::default();
                    while n.bits() != bits_len {
                        n = rng.sample(RandomBits::new(bits_len));
                    }
                    let n_square = &n * &n;

                    let spec = Spec::<F, T, RATE>::new(8, 57);

                    let mut partial_keys = vec![];

                    let mut aggregated_key = ExtractionKey2{
                        u: BigUint::from(1usize), v: BigUint::from(1usize), y: BigUint::from(1usize), w: BigUint::from(1usize),
                    };

                    for _ in 0..MAX_SEQUENCER_NUMBER2{
                        let u = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;
                        let v = rng.sample::<BigUint, _>(RandomBits::new(bits_len*2)) % &n_square;
                        let y = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;
                        let w = rng.sample::<BigUint, _>(RandomBits::new(bits_len*2)) % &n_square;

                        partial_keys.push(ExtractionKey2{u: u.clone(), v: v.clone(), y: y.clone(), w: w.clone()});


                        aggregated_key.u = aggregated_key.u * &u % &n;
                        aggregated_key.v = aggregated_key.v * &v % &n_square;
                        aggregated_key.y = aggregated_key.y * &y % &n;
                        aggregated_key.w = aggregated_key.w * &w % &n_square;
                    }

                    let mut ref_hasher = Poseidon::<F, T, RATE>::new_hash(8, 57);
                    let base1: F = big_to_fe(BigUint::from(
                        2_u128.pow(($circuit_name::<F, T, RATE>::LIMB_WIDTH as u128).try_into().unwrap()),
                    ));
                    let base2: F = base1 * &base1;

                    let mut hashes = vec![];

                    let limb_width = $circuit_name::<F, T, RATE>::LIMB_WIDTH;
                    let num_limbs = $circuit_name::<F, T, RATE>::BITS_LEN / $circuit_name::<F, T, RATE>::LIMB_WIDTH;

                    for i in 0..MAX_SEQUENCER_NUMBER2 {
                        let u = partial_keys[i].u.clone();
                        let u_limbs = decompose_big::<F>(u.clone(), num_limbs, limb_width);
                        for i in 0..(num_limbs / 3) {
                            let mut u_compose = u_limbs[3 * i];
                            u_compose += base1 * &u_limbs[3 * i + 1];
                            u_compose += base2 * &u_limbs[3 * i + 2];
                            ref_hasher.update(&[u_compose]);
                        }
                        let mut u_compose = u_limbs[30];
                        u_compose += base1 * &u_limbs[31];

                        let e = u_compose;
                        ref_hasher.update(&[e.clone()]);

                        let v = partial_keys[i].v.clone();
                        let v_limbs = decompose_big::<F>(v.clone(), num_limbs * 2, limb_width);
                        for i in 0..(num_limbs * 2 / 3) {
                            let mut v_compose = v_limbs[3 * i];
                            v_compose += base1 * &v_limbs[3 * i + 1];
                            v_compose += base2 * &v_limbs[3 * i + 2];
                            ref_hasher.update(&[v_compose]);
                        }
                        let mut v_compose = v_limbs[30];
                        v_compose += base1 * &v_limbs[31];
                        let e = v_compose;
                        ref_hasher.update(&[e.clone()]);

                        let y = partial_keys[i].y.clone();
                        let y_limbs = decompose_big::<F>(y.clone(), num_limbs, limb_width);
                        for i in 0..(num_limbs / 3) {
                            let mut y_compose = y_limbs[3 * i];
                            y_compose += base1 * &y_limbs[3 * i + 1];
                            y_compose += base2 * &y_limbs[3 * i + 2];
                            ref_hasher.update(&[y_compose]);
                        }
                        let mut y_compose = y_limbs[30];
                        y_compose += base1 * &y_limbs[31];
                        let e = y_compose;
                        ref_hasher.update(&[e.clone()]);

                        let w = partial_keys[i].w.clone();
                        let w_limbs = decompose_big::<F>(w.clone(), num_limbs * 2, limb_width);
                        for i in 0..(num_limbs * 2 / 3) {
                            let mut w_compose = w_limbs[3 * i];
                            w_compose += base1 * &w_limbs[3 * i + 1];
                            w_compose += base2 * &w_limbs[3 * i + 2];
                            ref_hasher.update(&[w_compose]);
                        }
                        let mut w_compose = w_limbs[30];
                        w_compose += base1 * &w_limbs[31];
                        let e = w_compose;
                        ref_hasher.update(&[e.clone()]);
                        let hash = ref_hasher.squeeze(1);
                        hashes.push(hash[1]);
                        hashes.push(hash[2]);
                    }

                    let circuit = $circuit_name::<F, T, RATE> {
                        partial_keys,
                        n,
                        spec,
                        n_square,
                        _f: PhantomData
                    };

                    let mut public_inputs = vec![hashes];
                    public_inputs[0].extend(decompose_big::<F>(aggregated_key.u.clone(), num_limbs, limb_width));
                    public_inputs[0].extend(decompose_big::<F>(aggregated_key.v.clone(), num_limbs * 2, limb_width));
                    public_inputs[0].extend(decompose_big::<F>(aggregated_key.y.clone(), num_limbs, limb_width));
                    public_inputs[0].extend(decompose_big::<F>(aggregated_key.w.clone(), num_limbs * 2, limb_width));


                    let k = 21;
                    let prover = match MockProver::run(k, &circuit, public_inputs) {
                        Ok(prover) => prover,
                        Err(e) => panic!("{:#?}", e)
                    };
                    assert_eq!(prover.verify().is_err(), $should_be_error);
                }

                use halo2wrong::curves::bn256::Fq as BnFq;
                // use halo2wrong::curves::pasta::{Fp as PastaFp, Fq as PastaFq};
                run::<BnFq, 5, 4>();
                // run::<PastaFp>();
                // run::<PastaFq>();
            }
        };
    }

    use crate::UnassignedInteger;

    impl_aggregate_with_hash_test_circuit!(
        TestAggregateWithHash2048Circuit,
        test_aggregate_with_hash_2048_circuit,
        2048, // this is bit length of n. n^2's length is the double of n's.
        false,
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let limb_width = Self::LIMB_WIDTH;
            let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
            let aggregate_with_hash_chip = self.aggregate_with_hash_chip(config.clone());
            let bigint_chip = aggregate_with_hash_chip.bigint_chip();
            let main_gate_chip = bigint_chip.main_gate();
            let bigint_square_chip = aggregate_with_hash_chip.bigint_square_chip();

            let instances = bigint_chip.main_gate().config().instance;

            let (u_out, v_out, y_out, w_out) = layouter.assign_region(
                || "Pick 2048bit u for partial keys",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let mut u_out = vec![];
                    let mut v_out = vec![];
                    let mut y_out = vec![];
                    let mut w_out = vec![];
                    for i in 0..MAX_SEQUENCER_NUMBER2 {
                        let u_limbs = decompose_big::<F>(
                            self.partial_keys[i].u.clone(),
                            num_limbs,
                            limb_width,
                        );
                        let u_unassigned = UnassignedInteger::from(u_limbs);
                        let u_assigned = bigint_chip.assign_integer(ctx, u_unassigned)?;
                        u_out.push(u_assigned);

                        let v_limbs = decompose_big::<F>(
                            self.partial_keys[i].v.clone(),
                            num_limbs * 2,
                            limb_width,
                        );
                        let v_unassigned = UnassignedInteger::from(v_limbs);
                        let v_assigned = bigint_square_chip.assign_integer(ctx, v_unassigned)?;
                        v_out.push(v_assigned);

                        let y_limbs = decompose_big::<F>(
                            self.partial_keys[i].y.clone(),
                            num_limbs,
                            limb_width,
                        );
                        let y_unassigned = UnassignedInteger::from(y_limbs);
                        let y_assigned = bigint_chip.assign_integer(ctx, y_unassigned)?;
                        y_out.push(y_assigned);

                        let w_limbs = decompose_big::<F>(
                            self.partial_keys[i].w.clone(),
                            num_limbs * 2,
                            limb_width,
                        );
                        let w_unassigned = UnassignedInteger::from(w_limbs);
                        let w_assigned = bigint_square_chip.assign_integer(ctx, w_unassigned)?;
                        w_out.push(w_assigned);
                    }
                    Ok((u_out, v_out, y_out, w_out))
                },
            )?;

            let hash_out = layouter.assign_region(
                || "hash mapping from 2048bit",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);
                    let mut hasher = AggregateWithHashChip::<F, T, RATE>::new_hash(
                        ctx,
                        &self.spec,
                        &config.hash_config.clone(),
                    )?;

                    let base1 = main_gate_chip.assign_constant(
                        ctx,
                        big_to_fe(BigUint::from(
                            2_u128.pow((Self::LIMB_WIDTH as u128).try_into().unwrap()),
                        )),
                    )?;
                    let base2 = main_gate_chip.mul(ctx, &base1, &base1)?;
                    // println!("base1 = {:?}", base1);

                    let mut hash_out = vec![];
                    for i in 0..MAX_SEQUENCER_NUMBER2 {
                        let u = u_out[i].clone();
                        for j in 0..u.num_limbs() / 3 {
                            // println!("limb({:?}) = {:?}", 3 * i, rsa_input.limb(3 * i));
                            // println!("limb({:?}) = {:?}", 3 * i + 1, rsa_input.limb(3 * i + 1));
                            // println!("limb({:?}) = {:?}", 3 * i + 2, rsa_input.limb(3 * i + 2));
                            let mut a_poly = u.limb(3 * j);
                            a_poly =
                                main_gate_chip.mul_add(ctx, &u.limb(3 * j + 1), &base1, &a_poly)?;
                            a_poly =
                                main_gate_chip.mul_add(ctx, &u.limb(3 * j + 2), &base2, &a_poly)?;
                            // println!("a_ploy value:{:?}", a_poly);
                            let e = a_poly;
                            hasher.update(&[e.clone()]);
                        }

                        let mut a_poly = u.limb(30);

                        a_poly = main_gate_chip.mul_add(ctx, &u.limb(31), &base1, &a_poly)?;
                        let e = a_poly;
                        hasher.update(&[e.clone()]);

                        let v = v_out[i].clone();
                        for j in 0..v.num_limbs() / 3 {
                            let mut a_poly = v.limb(3 * j);
                            a_poly =
                                main_gate_chip.mul_add(ctx, &v.limb(3 * j + 1), &base1, &a_poly)?;
                            a_poly =
                                main_gate_chip.mul_add(ctx, &v.limb(3 * j + 2), &base2, &a_poly)?;
                            let e = a_poly;
                            hasher.update(&[e.clone()]);
                        }

                        let mut a_poly = v.limb(30);

                        a_poly = main_gate_chip.mul_add(ctx, &v.limb(31), &base1, &a_poly)?;
                        let e = a_poly;
                        hasher.update(&[e.clone()]);

                        let y = y_out[i].clone();
                        for j in 0..y.num_limbs() / 3 {
                            let mut a_poly = y.limb(3 * j);
                            a_poly =
                                main_gate_chip.mul_add(ctx, &y.limb(3 * j + 1), &base1, &a_poly)?;
                            a_poly =
                                main_gate_chip.mul_add(ctx, &y.limb(3 * j + 2), &base2, &a_poly)?;
                            let e = a_poly;
                            hasher.update(&[e.clone()]);
                        }

                        let mut a_poly = y.limb(30);

                        a_poly = main_gate_chip.mul_add(ctx, &y.limb(31), &base1, &a_poly)?;
                        let e = a_poly;
                        hasher.update(&[e.clone()]);

                        let w = w_out[i].clone();
                        for j in 0..w.num_limbs() / 3 {
                            let mut a_poly = w.limb(3 * j);
                            a_poly =
                                main_gate_chip.mul_add(ctx, &w.limb(3 * j + 1), &base1, &a_poly)?;
                            a_poly =
                                main_gate_chip.mul_add(ctx, &w.limb(3 * j + 2), &base2, &a_poly)?;
                            let e = a_poly;
                            hasher.update(&[e.clone()]);
                        }

                        let mut a_poly = w.limb(30);

                        a_poly = main_gate_chip.mul_add(ctx, &w.limb(31), &base1, &a_poly)?;
                        let e = a_poly;
                        hasher.update(&[e.clone()]);

                        let h_assiged = hasher.hash(ctx)?;
                        hash_out.push(h_assiged[1].clone());
                        hash_out.push(h_assiged[2].clone());
                    }
                    Ok(hash_out)
                },
            )?;

            let mut index = 0;
            for hash in hash_out.iter() {
                layouter.constrain_instance(hash.cell(), instances, index)?;
                index += 1;
            }

            let valid_aggregated_key = layouter.assign_region(
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
                    for i in 0..MAX_SEQUENCER_NUMBER2 {
                        let assigned_extraction_key = AssignedAggregateWithHashExtractionKey::new(
                            u_out[i].clone(),
                            v_out[i].clone(),
                            y_out[i].clone(),
                            w_out[i].clone(),
                        );
                        partial_keys_assigned.push(assigned_extraction_key);
                    }
                    let partial_keys =
                        AssignedAggregateWithHashPartialKeys::new(partial_keys_assigned);

                    let public_params_unassigned = AggregateWithHashPublicParams::new(
                        n_unassigned.clone(),
                        n_square_unassigned.clone(),
                    );
                    let public_params = aggregate_with_hash_chip
                        .assign_public_params(ctx, public_params_unassigned)?;
                    let valid_aggregated_key = aggregate_with_hash_chip.aggregate_with_hash(
                        ctx,
                        &partial_keys.clone(),
                        &public_params.clone(),
                    )?;

                    Ok(valid_aggregated_key)
                },
            )?;

            (0..num_limbs).try_for_each(|i| -> Result<(), Error> {
                layouter.constrain_instance(
                    valid_aggregated_key.u.limb(i).cell(),
                    instances,
                    index,
                )?;
                index += 1;
                Ok(())
            })?;
            (0..num_limbs * 2).try_for_each(|i| -> Result<(), Error> {
                layouter.constrain_instance(
                    valid_aggregated_key.v.limb(i).cell(),
                    instances,
                    index,
                )?;
                index += 1;
                Ok(())
            })?;
            (0..num_limbs).try_for_each(|i| -> Result<(), Error> {
                layouter.constrain_instance(
                    valid_aggregated_key.y.limb(i).cell(),
                    instances,
                    index,
                )?;
                index += 1;
                Ok(())
            })?;
            (0..num_limbs * 2).try_for_each(|i| -> Result<(), Error> {
                layouter.constrain_instance(
                    valid_aggregated_key.w.limb(i).cell(),
                    instances,
                    index,
                )?;
                index += 1;
                Ok(())
            })?;

            let range_chip = bigint_chip.range_chip();
            let range_square_chip = bigint_square_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            range_square_chip.load_table(&mut layouter)?;

            Ok(())
        }
    );
}