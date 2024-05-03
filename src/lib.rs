pub mod big_integer;
pub use big_integer::*;
use ff::FromUniformBytes;
use maingate::big_to_fe;
use maingate::MainGateInstructions;
pub mod aggregate;
pub use crate::aggregate::*;
pub mod aggregate_with_hash;
pub use crate::aggregate_with_hash::*;
pub mod poseidon;
pub use crate::poseidon::*;
pub mod hash;
pub use crate::hash::*;
use ff::PrimeField;
use halo2wrong::{
    halo2::{
        circuit::{Chip, SimpleFloorPlanner},
        plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
    },
    RegionCtx,
};
use maingate::{decompose_big, mock_prover_verify, MainGate, RangeChip, RangeInstructions};
use num_bigint::BigUint;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct AggregateCircuit<F: PrimeField> {
    pub partial_keys: Vec<ExtractionKey>,
    pub aggregated_key: ExtractionKey,
    pub n: BigUint,
    pub n_square: BigUint,
    pub _f: PhantomData<F>,
}

impl<F: PrimeField> AggregateCircuit<F> {
    fn aggregate_chip(&self, config: AggregateConfig) -> AggregateChip<F> {
        AggregateChip::new(config, BITS_LEN)
    }
}
pub fn apply_aggregate_key_instance_constraints<F: PrimeField>(
    layouter: &mut impl halo2wrong::halo2::circuit::Layouter<F>,
    valid_agg_key_result: &AssignedExtractionKey<F>,
    num_limbs: usize,
    instances: Column<Instance>,
) -> Result<(), Error> {
    // let u_index = 0_usize;
    let y_index = num_limbs * 3;
    let v_index = num_limbs;
    let w_index = num_limbs * 4;

    (0..num_limbs).try_for_each(|i| -> Result<(), Error> {
        layouter.constrain_instance(valid_agg_key_result.u.limb(i).cell(), instances, i)?;
        layouter.constrain_instance(
            valid_agg_key_result.y.limb(i).cell(),
            instances,
            y_index + i,
        )
    })?;

    (0..num_limbs * 2).try_for_each(|i| -> Result<(), Error> {
        layouter.constrain_instance(
            valid_agg_key_result.v.limb(i).cell(),
            instances,
            v_index + i,
        )?;
        layouter.constrain_instance(
            valid_agg_key_result.w.limb(i).cell(),
            instances,
            w_index + i,
        )
    })?;
    Ok(())
}

fn apply_partial_key_instance_constraints<F: PrimeField>(
    layouter: &mut impl halo2wrong::halo2::circuit::Layouter<F>,
    partial_key_result: &AssignedAggregatePartialKeys<F>,
    num_limbs: usize,
    instances: Column<Instance>,
) -> Result<(), Error> {
    (0..MAX_SEQUENCER_NUMBER).try_for_each(|k| -> Result<(), Error> {
        let u_limb = &partial_key_result.partial_keys[k].u;
        let v_limb = &partial_key_result.partial_keys[k].v;
        let y_limb = &partial_key_result.partial_keys[k].y;
        let w_limb = &partial_key_result.partial_keys[k].w;

        let base_index = k * 6 * num_limbs;
        let u_index = base_index + num_limbs * 6;
        let v_index = base_index + num_limbs * 7;
        let y_index = base_index + num_limbs * 9;
        let w_index = base_index + num_limbs * 10;

        (0..num_limbs).try_for_each(|i| -> Result<(), Error> {
            layouter.constrain_instance(u_limb.limb(i).cell(), instances, u_index + i)?;
            layouter.constrain_instance(y_limb.limb(i).cell(), instances, y_index + i)
        })?;

        (0..num_limbs * 2).try_for_each(|i| -> Result<(), Error> {
            layouter.constrain_instance(v_limb.limb(i).cell(), instances, v_index + i)?;
            layouter.constrain_instance(w_limb.limb(i).cell(), instances, w_index + i)
        })?;

        Ok(())
    })
}
impl<F: PrimeField> Circuit<F> for AggregateCircuit<F> {
    type Config = AggregateConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let main_gate_config = MainGate::<F>::configure(meta);
        let (composition_bit_lens, overflow_bit_lens) =
            AggregateChip::<F>::compute_range_lens(BITS_LEN / LIMB_WIDTH);
        let range_config = RangeChip::<F>::configure(
            meta,
            &main_gate_config,
            composition_bit_lens,
            overflow_bit_lens,
        );
        let (square_composition_bit_lens, square_overflow_bit_lens) =
            AggregateChip::<F>::compute_range_lens(BITS_LEN * 2 / LIMB_WIDTH);
        let square_range_config = RangeChip::<F>::configure(
            meta,
            &main_gate_config,
            square_composition_bit_lens,
            square_overflow_bit_lens,
        );
        let bigint_config = BigIntConfig::new(range_config.clone(), main_gate_config.clone());
        let bigint_square_config =
            BigIntConfig::new(square_range_config.clone(), main_gate_config.clone());

        Self::Config {
            bigint_config,
            bigint_square_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    ) -> Result<(), Error> {
        let aggregate_chip = self.aggregate_chip(config);
        let bigint_chip = aggregate_chip.bigint_chip();
        let bigint_square_chip = aggregate_chip.bigint_square_chip();
        let limb_width = LIMB_WIDTH;
        let num_limbs = BITS_LEN / LIMB_WIDTH;
        let (partial_keys_result, valid_agg_key_result) = layouter.assign_region(
            || "aggregate key test with 2048 bits RSA parameter",
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
                    let decomposed_partial_key =
                        aggregate::chip::ExtractionKey::decompose_extraction_key(
                            &self.partial_keys[i],
                        );

                    let (u_unassigned, v_unassigned, y_unassigned, w_unassigned) =
                        decomposed_partial_key.to_unassigned_integers();

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

                let public_params_unassigned =
                    AggregatePublicParams::new(n_unassigned.clone(), n_square_unassigned.clone());
                let public_params =
                    aggregate_chip.assign_public_params(ctx, public_params_unassigned)?;
                let valid_agg_key =
                    aggregate_chip.aggregate(ctx, &partial_keys.clone(), &public_params.clone())?;

                Ok((partial_keys, valid_agg_key))
            },
        )?;

        let instances = bigint_chip.main_gate().config().instance;

        apply_aggregate_key_instance_constraints(
            &mut layouter,
            &valid_agg_key_result,
            num_limbs,
            instances,
        )?;

        apply_partial_key_instance_constraints(
            &mut layouter,
            &partial_keys_result,
            num_limbs,
            instances,
        )?;

        let range_chip = bigint_chip.range_chip();
        let range_square_chip = bigint_square_chip.range_chip();
        range_chip.load_table(&mut layouter)?;
        range_square_chip.load_table(&mut layouter)?;

        Ok(())
    }
}


#[derive(Clone, Debug)]
pub struct AggregateWithHashCircuit<F: PrimeField, const T: usize, const RATE: usize> {
    pub partial_keys: Vec<ExtractionKey2>,
    pub n: BigUint,
    pub spec: Spec<F, T, RATE>,
    pub n_square: BigUint,
    pub _f: PhantomData<F>,
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize>
    AggregateWithHashCircuit<F, T, RATE>
{
    pub const BITS_LEN: usize = 2048; // n's bit length
    pub const LIMB_WIDTH: usize = AggregateWithHashChip::<F, T, RATE>::LIMB_WIDTH;
    fn aggregate_with_hash_chip(
        &self,
        config: AggregateWithHashConfig,
    ) -> AggregateWithHashChip<F, T, RATE> {
        AggregateWithHashChip::new(config, Self::BITS_LEN)
    }
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize> Circuit<F>
    for AggregateWithHashCircuit<F, T, RATE>
{
    type Config = AggregateWithHashConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
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
        let bigint_square_config =
            BigIntConfig::new(square_range_config.clone(), main_gate_config.clone());

        let hash_config = main_gate_config.clone();

        Self::Config {
            bigint_config,
            bigint_square_config,
            hash_config,
        }
    }

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
                    let u_limbs =
                        decompose_big::<F>(self.partial_keys[i].u.clone(), num_limbs, limb_width);
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

                    let y_limbs =
                        decompose_big::<F>(self.partial_keys[i].y.clone(), num_limbs, limb_width);
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
                let partial_keys = AssignedAggregateWithHashPartialKeys::new(partial_keys_assigned);

                let public_params_unassigned = AggregateWithHashPublicParams::new(
                    n_unassigned.clone(),
                    n_square_unassigned.clone(),
                );
                let public_params =
                    aggregate_with_hash_chip.assign_public_params(ctx, public_params_unassigned)?;
                let valid_aggregated_key = aggregate_with_hash_chip.aggregate_with_hash(
                    ctx,
                    &partial_keys.clone(),
                    &public_params.clone(),
                )?;

                Ok(valid_aggregated_key)
            },
        )?;

        (0..num_limbs).try_for_each(|i| -> Result<(), Error> {
            layouter.constrain_instance(valid_aggregated_key.u.limb(i).cell(), instances, index)?;
            index += 1;
            Ok(())
        })?;
        (0..num_limbs * 2).try_for_each(|i| -> Result<(), Error> {
            layouter.constrain_instance(valid_aggregated_key.v.limb(i).cell(), instances, index)?;
            index += 1;
            Ok(())
        })?;
        (0..num_limbs).try_for_each(|i| -> Result<(), Error> {
            layouter.constrain_instance(valid_aggregated_key.y.limb(i).cell(), instances, index)?;
            index += 1;
            Ok(())
        })?;
        (0..num_limbs * 2).try_for_each(|i| -> Result<(), Error> {
            layouter.constrain_instance(valid_aggregated_key.w.limb(i).cell(), instances, index)?;
            index += 1;
            Ok(())
        })?;

        let range_chip = bigint_chip.range_chip();
        let range_square_chip = bigint_square_chip.range_chip();
        range_chip.load_table(&mut layouter)?;
        range_square_chip.load_table(&mut layouter)?;

        Ok(())
    }
}


#[test]
fn test_aggregate_circuit() {
    use halo2wrong::curves::bn256::Fr;
    use num_bigint::RandomBits;
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    let bits_len = BITS_LEN as u64;
    let mut n = BigUint::default();
    while n.bits() != bits_len {
        n = rng.sample(RandomBits::new(bits_len));
    }
    let n_square = &n * &n;

    let mut partial_keys = vec![];

    let mut aggregated_key = ExtractionKey {
        u: BigUint::from(1usize),
        v: BigUint::from(1usize),
        y: BigUint::from(1usize),
        w: BigUint::from(1usize),
    };

    for _ in 0..MAX_SEQUENCER_NUMBER {
        let u = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;
        let v = rng.sample::<BigUint, _>(RandomBits::new(bits_len * 2)) % &n_square;
        let y = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;
        let w = rng.sample::<BigUint, _>(RandomBits::new(bits_len * 2)) % &n_square;

        partial_keys.push(ExtractionKey {
            u: u.clone(),
            v: v.clone(),
            y: y.clone(),
            w: w.clone(),
        });

        aggregated_key.u = aggregated_key.u * &u % &n;
        aggregated_key.v = aggregated_key.v * &v % &n_square;
        aggregated_key.y = aggregated_key.y * &y % &n;
        aggregated_key.w = aggregated_key.w * &w % &n_square;
    }

    let combined_partial_limbs: Vec<Fr> =
        aggregate::chip::ExtractionKey::decompose_and_combine_all_partial_keys(
            partial_keys.clone(),
        );

    let decomposed_extraction_key: DecomposedExtractionKey<Fr> =
        aggregate::chip::ExtractionKey::decompose_extraction_key(&aggregated_key);
    let mut combined_limbs = decomposed_extraction_key.combine_limbs();

    let circuit = AggregateCircuit::<Fr> {
        partial_keys,
        aggregated_key,
        n,
        n_square,
        _f: PhantomData,
    };

    combined_limbs.extend(combined_partial_limbs);

    let public_inputs = vec![combined_limbs];
    mock_prover_verify(&circuit, public_inputs);
}


#[test]
fn test_aggregate_with_hash_circuit() {
    use halo2wrong::curves::bn256::Fr;
    use num_bigint::RandomBits;
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    let bits_len = AggregateWithHashCircuit::<Fr, 5, 4>::BITS_LEN as u64;
    let mut n = BigUint::default();
    while n.bits() != bits_len {
        n = rng.sample(RandomBits::new(bits_len));
    }
    let n_square = &n * &n;

    let spec = Spec::<Fr, 5, 4>::new(8, 57);

    let mut partial_keys = vec![];

    let mut aggregated_key = ExtractionKey2 {
        u: BigUint::from(1usize),
        v: BigUint::from(1usize),
        y: BigUint::from(1usize),
        w: BigUint::from(1usize),
    };

    for _ in 0..MAX_SEQUENCER_NUMBER2 {
        let u = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;
        let v = rng.sample::<BigUint, _>(RandomBits::new(bits_len * 2)) % &n_square;
        let y = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;
        let w = rng.sample::<BigUint, _>(RandomBits::new(bits_len * 2)) % &n_square;

        partial_keys.push(ExtractionKey2 {
            u: u.clone(),
            v: v.clone(),
            y: y.clone(),
            w: w.clone(),
        });

        aggregated_key.u = aggregated_key.u * &u % &n;
        aggregated_key.v = aggregated_key.v * &v % &n_square;
        aggregated_key.y = aggregated_key.y * &y % &n;
        aggregated_key.w = aggregated_key.w * &w % &n_square;
    }

    let mut ref_hasher = Poseidon::<Fr, 5, 4>::new_hash(8, 57);
    let base1: Fr = big_to_fe(BigUint::from(
        2_u128.pow(
            (AggregateWithHashCircuit::<Fr, 5, 4>::LIMB_WIDTH as u128)
                .try_into()
                .unwrap(),
        ),
    ));
    let base2: Fr = base1 * &base1;

    let mut hashes = vec![];

    let limb_width = AggregateWithHashCircuit::<Fr, 5, 4>::LIMB_WIDTH;
    let num_limbs = AggregateWithHashCircuit::<Fr, 5, 4>::BITS_LEN
        / AggregateWithHashCircuit::<Fr, 5, 4>::LIMB_WIDTH;

    for i in 0..MAX_SEQUENCER_NUMBER2 {
        let u = partial_keys[i].u.clone();
        let u_limbs = decompose_big::<Fr>(u.clone(), num_limbs, limb_width);
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
        let v_limbs = decompose_big::<Fr>(v.clone(), num_limbs * 2, limb_width);
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
        let y_limbs = decompose_big::<Fr>(y.clone(), num_limbs, limb_width);
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
        let w_limbs = decompose_big::<Fr>(w.clone(), num_limbs * 2, limb_width);
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

    let circuit = AggregateWithHashCircuit::<Fr, 5, 4> {
        partial_keys,
        n,
        spec,
        n_square,
        _f: PhantomData,
    };

    let mut public_inputs = vec![hashes];
    public_inputs[0].extend(decompose_big::<Fr>(
        aggregated_key.u.clone(),
        num_limbs,
        limb_width,
    ));
    public_inputs[0].extend(decompose_big::<Fr>(
        aggregated_key.v.clone(),
        num_limbs * 2,
        limb_width,
    ));
    public_inputs[0].extend(decompose_big::<Fr>(
        aggregated_key.y.clone(),
        num_limbs,
        limb_width,
    ));
    public_inputs[0].extend(decompose_big::<Fr>(
        aggregated_key.w.clone(),
        num_limbs * 2,
        limb_width,
    ));
    mock_prover_verify(&circuit, public_inputs);
}