pub mod big_integer;
pub use big_integer::*;
pub mod aggregate;
pub use crate::aggregate::*;
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
