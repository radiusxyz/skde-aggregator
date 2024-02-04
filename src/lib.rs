pub mod big_integer;
pub use big_integer::*;
pub mod aggregate;
pub use crate::aggregate::*;
use ff::PrimeField;
use halo2wrong::{
    halo2::{
        circuit::SimpleFloorPlanner,
        plonk::{Circuit, ConstraintSystem, Error},
    },
    RegionCtx,
};
use maingate::{decompose_big, MainGate, RangeChip, RangeInstructions};
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
    pub const BITS_LEN: usize = 2048; // n's bit length
    pub const LIMB_WIDTH: usize = AggregateChip::<F>::LIMB_WIDTH;
    pub const MAX_SEQUENCER_NUMBER: usize = MAX_SEQUENCER_NUMBER;
    fn aggregate_chip(&self, config: AggregateConfig) -> AggregateChip<F> {
        AggregateChip::new(config, Self::BITS_LEN)
    }
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
            AggregateChip::<F>::compute_range_lens(Self::BITS_LEN / Self::LIMB_WIDTH);
        let range_config = RangeChip::<F>::configure(
            meta,
            &main_gate_config,
            composition_bit_lens,
            overflow_bit_lens,
        );
        let (square_composition_bit_lens, square_overflow_bit_lens) =
            AggregateChip::<F>::compute_range_lens(Self::BITS_LEN * 2 / Self::LIMB_WIDTH);
        let square_range_config = RangeChip::<F>::configure(
            meta,
            &main_gate_config,
            square_composition_bit_lens,
            square_overflow_bit_lens,
        );
        let bigint_config = BigIntConfig::new(range_config.clone(), main_gate_config.clone());
        let bigint_square_config =
            BigIntConfig::new(square_range_config.clone(), main_gate_config.clone());

        //TODO add instance to check agg key
        // let instance = meta.instance_column();
        // meta.enable_equality(instance);

        Self::Config {
            bigint_config,
            bigint_square_config,
            // instance
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
                for i in 0..Self::MAX_SEQUENCER_NUMBER {
                    let u_limbs =
                        decompose_big::<F>(self.partial_keys[i].u.clone(), num_limbs, limb_width);
                    let u_unassigned = UnassignedInteger::from(u_limbs);

                    let v_limbs = decompose_big::<F>(
                        self.partial_keys[i].v.clone(),
                        num_limbs * 2,
                        limb_width,
                    );
                    let v_unassigned = UnassignedInteger::from(v_limbs);

                    let y_limbs =
                        decompose_big::<F>(self.partial_keys[i].y.clone(), num_limbs, limb_width);
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
                let agg_v_limb =
                    decompose_big::<F>(self.aggregated_key.v.clone(), num_limbs * 2, limb_width);
                let agg_y_limbs =
                    decompose_big::<F>(self.aggregated_key.y.clone(), num_limbs, limb_width);
                let agg_w_limb =
                    decompose_big::<F>(self.aggregated_key.w.clone(), num_limbs * 2, limb_width);
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

                let public_params_unassigned =
                    AggregatePublicParams::new(n_unassigned.clone(), n_square_unassigned.clone());
                let public_params =
                    aggregate_chip.assign_public_params(ctx, public_params_unassigned)?;
                let valid_agg_key =
                    aggregate_chip.aggregate(ctx, &partial_keys.clone(), &public_params.clone())?;

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
}

#[test]
fn test_aggregate_circuit() {
    use halo2wrong::curves::bn256::Fq;
    use halo2wrong::halo2::dev::MockProver;
    use num_bigint::RandomBits;
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    let bits_len = AggregateCircuit::<Fq>::BITS_LEN as u64;
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

    for _ in 0..AggregateCircuit::<Fq>::MAX_SEQUENCER_NUMBER {
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

    let circuit = AggregateCircuit::<Fq> {
        partial_keys,
        aggregated_key,
        n,
        n_square,
        _f: PhantomData,
    };

    let public_inputs = vec![vec![]];
    let k = 20;
    let prover = match MockProver::run(k, &circuit, public_inputs) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify().is_err(), false);
}
