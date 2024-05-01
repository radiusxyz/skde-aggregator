pub mod big_integer;
pub use big_integer::*;
use num_traits::{One, Zero};
use rand::{rngs::StdRng, SeedableRng};
use sha2::{Digest, Sha256};
pub mod aggregate;
pub use crate::aggregate::*;
pub mod maingate;
use ff::PrimeField;
use halo2_proofs::{
    circuit::{Chip, Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    halo2curves::bn256::Fr,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance},
};
use hash_circuit::hash::*;
use hash_circuit::{poseidon::*, DEFAULT_STEP};
use maingate::{
    instructions::{big_to_fe, decompose_big},
    MainGate, MainGateInstructions, RangeChip, RangeInstructions, RegionCtx,
};
use num_bigint::{BigUint, RandBigInt};
use std::{borrow::Borrow, collections::hash_map::Values, hash::Hash, iter::repeat_with, marker::PhantomData};
// 2048(u) + 4096(v) + 2048(y) + 4096(w) = 12288 (1536 byte)
// message length in byte
const MSG_LEN: u64 = 1536;
const EK_STEP: usize = 32;
const ITER: usize = (MSG_LEN as usize/ EK_STEP) + 1; //49
#[derive(Clone, Debug)]
pub struct CommitAndAggregationConfig<F: Hashable, PC: PermuteChip<F, F::SpecType, 3, 2>> {
    pub bigint_config: BigIntConfig,
    pub bigint_square_config: BigIntConfig,
    // Configuration for Sponge.
    pub sponge_configs: Vec<SpongeConfig<F, PC>>,
}

#[derive(Clone, Debug)]
pub struct CommitAndAggregationCircuit<PC> {
    pub poseidon_tables: Vec<PoseidonHashTable<Fr>>,
    // pub poseidon_table: PoseidonHashTable<Fr>,
    // pub config: SpongeConfig<Fr>,
    pub hashed_values: Vec<Fr>,
    pub partial_keys: Vec<ExtractionKey>,
    pub aggregated_key: ExtractionKey,
    pub n: BigUint,
    pub n_square: BigUint,
    _phantom: PhantomData<PC>,
}

pub fn apply_aggregate_key_instance_constraints<F: PrimeField>(
    layouter: &mut impl Layouter<F>,
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

impl<PC: PermuteChip<Fr, <Fr as Hashable>::SpecType, 3, 2>> CommitAndAggregationCircuit<PC> {
    pub fn new(
        hashed_values: Vec<Fr>,
        partial_keys: Vec<ExtractionKey>,
        aggregated_key: ExtractionKey,
        n: BigUint,
    ) -> Self {
        

        let ctr: Vec<u64> = (0..ITER as u64).map(|i| MSG_LEN - i * 32).collect();

        let formatted_key_vecs: Vec<Vec<BigUint>> =
            CommitAndAggregationCircuit::<PC>::format_extraction_keys(&partial_keys);
        // let formatted_key_vecs: Vec<Vec<BigUint>> = partial_keys
        //     .iter()
        //     .map(|key| {
        //         [&key.u, &key.v, &key.y, &key.w]
        //             .iter()
        //             .flat_map(|&field| {
        //                 let chunk_size = BigUint::one() << 128;
        //                 repeat_with({
        //                     let mut value = field.clone();
        //                     move || {
        //                         if value > Zero::zero() {
        //                             let chunk = &value % &chunk_size;
        //                             value >>= 128; // 16 byte
        //                             Some(chunk)
        //                         } else {
        //                             None
        //                         }
        //                     }
        //                 })
        //                 .take_while(Option::is_some)
        //                 .map(Option::unwrap)
        //             })
        //             .collect()
        //     })
        //     .collect();

        // for (index, formatted_key) in formatted_key_vecs.iter().enumerate() {
        //     let hex_strings: Vec<String> = formatted_key
        //         .iter()
        //         .map(|num| num.to_str_radix(16))
        //         .collect();
        //     println!("Key {}: {:?}", index, hex_strings.join(", "));
        // }
        // println!("THE LEN: {:?}", formatted_key_vecs[0].len());
        // 1536 / 32 = 48 (iteration)
        // 1536 * HASHABLE_DOMAIN_SPEC = 37778931862957161709568 (0x0000000000000000000000000000000000000000000008000000000000000000)
        // HASHABLE_DOMAIN_SPEC = 18446744073709551616 (0x10000000000000000)

        let supposed_bytes = MSG_LEN as u128 * HASHABLE_DOMAIN_SPEC;

        // let computed_hash: Vec<Fr> = formatted_key_vecs
        //     .iter()
        //     .map(|formatted_key| {
        //         let mapped_partial_key: Vec<Fr> = formatted_key
        //             .iter()
        //             .map(|biguint| {
        //                 let decimal_str = biguint.to_str_radix(10);
        //                 Fr::from_str_vartime(&decimal_str).unwrap()
        //             })
        //             .collect();

        //         let hash_circuit_input: Vec<[Fr; 2]> = mapped_partial_key.chunks_exact(2)
        //         .map(|chunk| {
        //             [chunk[0], chunk[1]]
        //         })
        //         .collect();

        //         Fr::hash_msg(&mapped_partial_key, Some(supposed_bytes))
        //     })
        //     .collect();

        let (computed_hash, hash_circuit_input): (Vec<Fr>, Vec<Vec<[Fr; 2]>>) =
            formatted_key_vecs.iter().fold(
                (Vec::new(), Vec::new()),
                |(computed_hash, hash_circuit_input), formatted_key| {
                    let mapped_partial_key: Vec<Fr> = formatted_key
                        .iter()
                        .map(|biguint| {
                            let decimal_str = biguint.to_str_radix(10);
                            Fr::from_str_vartime(&decimal_str).unwrap()
                        })
                        .collect();

                    let current_hash = Fr::hash_msg(&mapped_partial_key, Some(supposed_bytes));

                    let current_hash_circuit_input: Vec<[Fr; 2]> = mapped_partial_key
                        .chunks_exact(2)
                        .map(|chunk| [chunk[0], chunk[1]])
                        .collect();

                    (
                        computed_hash
                            .into_iter()
                            .chain(Some(current_hash))
                            .collect(),
                        hash_circuit_input
                            .into_iter()
                            .chain(Some(current_hash_circuit_input))
                            .collect(),
                    )
                },
            );

        println!("computed_hash = {:?}", computed_hash);

        let computed_results: Vec<[Option<Fr>; ITER+1]> = computed_hash
        .iter()
        .map(|&value| {
            let mut array = [None; ITER+1];
            array[ITER] = Some(value);
            array
        })
        .collect();

        let poseidon_tables: Vec<PoseidonHashTable<_>> = (0..hash_circuit_input.len())
            .map(|i| PoseidonHashTable {
                inputs: hash_circuit_input[i].iter().take(ITER - 1).cloned().collect(),
                controls: ctr.clone(),
                checks: computed_results[i].to_vec(),
                ..Default::default()
            })
            .collect();

        // assert_eq!(computed_hash[0], hashed_values[0]);
        CommitAndAggregationCircuit {
            poseidon_tables: poseidon_tables,
            // poseidon_table: tmp,
            hashed_values,
            partial_keys,
            aggregated_key,
            n: n.clone(),
            n_square: &n * &n,
            _phantom: PhantomData,
        }
    }

    pub fn format_extraction_keys(partial_keys: &Vec<ExtractionKey>) -> Vec<Vec<BigUint>> {
        let formatted_keys: Vec<Vec<BigUint>> = partial_keys
            .iter()
            .map(|key| {
                [&key.u, &key.v, &key.y, &key.w]
                    .iter()
                    .flat_map(|&field| {
                        let chunk_size = BigUint::one() << 128;
                        repeat_with({
                            let mut value = field.clone();
                            move || {
                                if value > Zero::zero() {
                                    let chunk = &value % &chunk_size;
                                    value >>= 128; // 16 byte
                                    Some(chunk)
                                } else {
                                    None
                                }
                            }
                        })
                        .take_while(Option::is_some)
                        .map(Option::unwrap)
                    })
                    .collect()
            })
            .collect();

        formatted_keys
    }
    pub fn aggregate_chip(&self, config: CommitAndAggregationConfig<Fr, PC>) -> AggregateChip<Fr> {
        let aggregate_config = AggregateConfig {
            bigint_config: config.bigint_config,
            bigint_square_config: config.bigint_square_config,
        };
        AggregateChip::new(aggregate_config, BITS_LEN)
    }
}

impl<PC: PermuteChip<Fr, <Fr as Hashable>::SpecType, 3, 2>> Circuit<Fr>
    for CommitAndAggregationCircuit<PC>
where
    PC::Config: Sync,
{
    type Config = CommitAndAggregationConfig<Fr, PC>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let main_gate_config = MainGate::<Fr>::configure(meta);
        let (composition_bit_lens, overflow_bit_lens) =
            AggregateChip::<Fr>::compute_range_lens(BITS_LEN / LIMB_WIDTH);
        let range_config = RangeChip::<Fr>::configure(
            meta,
            &main_gate_config,
            composition_bit_lens,
            overflow_bit_lens,
        );
        let (square_composition_bit_lens, square_overflow_bit_lens) =
            AggregateChip::<Fr>::compute_range_lens(BITS_LEN * 2 / LIMB_WIDTH);
        let square_range_config = RangeChip::<Fr>::configure(
            meta,
            &main_gate_config,
            square_composition_bit_lens,
            square_overflow_bit_lens,
        );
        let bigint_config = BigIntConfig::new(range_config.clone(), main_gate_config.clone());
        let bigint_square_config =
            BigIntConfig::new(square_range_config.clone(), main_gate_config.clone());

        let hash_tbls: [[Column<Advice>; 6]; MAX_SEQUENCER_NUMBER] =
            [[0; 6].map(|_| meta.advice_column()); MAX_SEQUENCER_NUMBER];
        let q_enables: [Column<Fixed>; MAX_SEQUENCER_NUMBER] =
            [0; MAX_SEQUENCER_NUMBER].map(|_| meta.fixed_column());
        // let sponge_config = SpongeConfig::configure_sub(meta, (q_enable, hash_tbl), EK_STEP);
        let sponge_configs = q_enables
            .iter()
            .zip(hash_tbls.iter())
            .map(|(q_enable, hash_tbl)| {
                SpongeConfig::configure_sub(meta, (*q_enable, *hash_tbl), EK_STEP)
            })
            .collect();

        Self::Config {
            bigint_config,
            bigint_square_config,
            sponge_configs,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let aggregate_chip = self.aggregate_chip(config.clone());
        let bigint_chip = aggregate_chip.bigint_chip();
        let bigint_square_chip = aggregate_chip.bigint_square_chip();
        // let main_gate = aggregate_chip.bigint_chip().main_gate();
        let limb_width = LIMB_WIDTH;
        let num_limbs = BITS_LEN / LIMB_WIDTH;
        let valid_agg_key_result = layouter.assign_region(
            || "aggregate key test with 2048 bits RSA parameter",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                let n_limbs = decompose_big::<Fr>(self.n.clone(), num_limbs, limb_width);
                let n_unassigned = UnassignedInteger::from(n_limbs);

                let n_square_limbs =
                    decompose_big::<Fr>(self.n_square.clone(), num_limbs * 2, limb_width);
                let n_square_unassigned = UnassignedInteger::from(n_square_limbs);

                let partial_keys_assigned: Result<Vec<_>, _> = (0..MAX_SEQUENCER_NUMBER)
                    .map(|i| {
                        let decomposed_partial_key =
                            ExtractionKey::decompose_extraction_key(&self.partial_keys[i]);
                        let (u_unassigned, v_unassigned, y_unassigned, w_unassigned) =
                            decomposed_partial_key.to_unassigned_integers();
                        let extraction_key_unassigned = AggregateExtractionKey::new(
                            u_unassigned,
                            v_unassigned,
                            y_unassigned,
                            w_unassigned,
                        );

                        // let extraction_key_unassigned = self.poseidon_tables[0].inputs;
                        aggregate_chip.assign_extraction_key(ctx, extraction_key_unassigned)
                    })
                    .collect();

                let partial_keys_assigned = partial_keys_assigned.map(|keys| {
                    // println!("u.limbs() {:?}", keys[0].u.limbs());
                    AssignedAggregatePartialKeys::new(keys)
                })?;

                let public_params_unassigned =
                    AggregatePublicParams::new(n_unassigned.clone(), n_square_unassigned.clone());
                let public_params =
                    aggregate_chip.assign_public_params(ctx, public_params_unassigned)?;
                let valid_agg_key = aggregate_chip.aggregate(
                    ctx,
                    &partial_keys_assigned.clone(),
                    &public_params.clone(),
                )?;

                Ok(valid_agg_key)
            },
        )?;

        let instances = bigint_chip.main_gate().config().instance;

        apply_aggregate_key_instance_constraints(
            &mut layouter,
            &valid_agg_key_result,
            num_limbs,
            instances,
        )?;

        let range_chip = bigint_chip.range_chip();
        let range_square_chip = bigint_square_chip.range_chip();
        range_chip.load_table(&mut layouter)?;
        range_square_chip.load_table(&mut layouter)?;

        let sponge_chips: Vec<SpongeChip<Fr, EK_STEP, PC>> = config
            .sponge_configs
            .iter()
            .zip(self.poseidon_tables.iter())
            .map(|(sponge_config, poseidon_table)| {
                SpongeChip::<Fr, EK_STEP, PC>::construct(sponge_config.clone(), poseidon_table, ITER)
            })
            .collect();

        for sponge_chip in sponge_chips {
            sponge_chip.load(&mut layouter);  
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::halo2curves::bn256::Fr;
    use hash_circuit::HASHABLE_DOMAIN_SPEC;
    use num_bigint::RandomBits;
    use rand::{thread_rng, Rng};
    #[test]
    fn test_circuit() {
        test_commit_and_aggregate_circuit::<Pow5Chip<Fr, 3, 2>>();
        // poseidon_hash_circuit_impl::<SeptidonChip>();
    }

    fn test_commit_and_aggregate_circuit<PC: PermuteChip<Fr, <Fr as Hashable>::SpecType, 3, 2>>()
    where
        PC::Config: Sync,
    {
        let mut rng = thread_rng();
        let bits_len = BITS_LEN as u64;
        let mut n = BigUint::default();
        while n.bits() != bits_len {
            n = rng.sample(RandomBits::new(bits_len));
        }

        // let seed_str = "example deterministic seed";
        // let mut hasher = Sha256::new();
        // hasher.update(seed_str);
        // let seed_bytes = hasher.finalize();
        // let seed =
        //     <[u8; 32]>::try_from(seed_bytes.as_slice()).expect("SHA256 is always 32 bytes; qed");

        // let mut rng = StdRng::from_seed(seed); // fixed seed
        // let n = rng.gen_biguint(bits_len);
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

            // let u = rng.gen_biguint(bits_len) % &n;
            // let v = rng.gen_biguint(bits_len * 2) % &n_square;
            // let y = rng.gen_biguint(bits_len) % &n;
            // let w = rng.gen_biguint(bits_len * 2) % &n_square;

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

        let decomposed_extraction_key: DecomposedExtractionKey<Fr> =
            crate::ExtractionKey::decompose_extraction_key(&aggregated_key);
        let mut combined_limbs = decomposed_extraction_key.combine_limbs();
        // 6151808128436302227947693167395663590637705150914724865306430048708093150080 (0x0d99cccd7a7b928b414da742296875e18a5ba980ce93470082ec6c73f62a0380)

        let message_len = 1536;

        let formatted_key_vecs: Vec<Vec<BigUint>> =
            CommitAndAggregationCircuit::<PC>::format_extraction_keys(&partial_keys);
        let supposed_bytes = message_len as u128 * HASHABLE_DOMAIN_SPEC;

        let hashed: Vec<Fr> = formatted_key_vecs
            .iter()
            .map(|formatted_key| {
                let mapped_partial_key: Vec<Fr> = formatted_key
                    .iter()
                    .map(|biguint| {
                        let decimal_str = biguint.to_str_radix(10);
                        Fr::from_str_vartime(&decimal_str).unwrap()
                    })
                    .collect();

                Fr::hash_msg(&mapped_partial_key, Some(supposed_bytes))
            })
            .collect();

        let c: CommitAndAggregationCircuit<PC> =
            CommitAndAggregationCircuit::<PC>::new(hashed.clone(), partial_keys, aggregated_key, n);
        // combined_limbs.extend(combined_partial_limbs);
        combined_limbs.extend(hashed.clone());

        for value in hashed.clone() {
            println!("HASHED: {:?}", value);
        }

        let public_inputs = vec![combined_limbs]; // aggregated key & hash of partial keys

        let k = 20;
        let prover = match MockProver::run(k, &c, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify().is_err(), false);
    }
}
