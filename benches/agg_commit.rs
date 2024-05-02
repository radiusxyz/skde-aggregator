use ff::PrimeField;
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
use halo2_proofs::{
    plonk::*,
    poly::{commitment::Params, VerificationStrategy},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::AccumulatorStrategy,
        },
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
    SerdeFormat,
};

use hash_circuit::hash::MessageHashable;
use hash_circuit::poseidon::{PermuteChip, Pow5Chip};
use skde_aggregator::{
    CommitAndAggregationCircuit, DecomposedExtractionKey, ExtractionKey, BITS_LEN,
    MAX_SEQUENCER_NUMBER,
};
use hash_circuit::{Hashable, HASHABLE_DOMAIN_SPEC};

use num_bigint::{BigUint, RandomBits};
use rand::{thread_rng, Rng};
use rand_core::OsRng;
use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, Read, Write},
    path::Path,
};
// bench-mark tool
use criterion::Criterion;

// Create the file and directory if it does not exist
fn ensure_directory_exists(path: &Path) {
    if let Some(parent) = path.parent() {
        let _ = fs::remove_file(path);
        fs::create_dir_all(parent).expect("Failed to create directories");
    }
}

fn write_to_file<P: AsRef<Path>>(path: P, data: &[u8]) {
    ensure_directory_exists(path.as_ref());
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .expect("Failed to open or create file");
    file.write_all(data).expect("Failed to write to file");
    file.flush().expect("Failed to flush file");
}

fn bench_aggregate<PC: PermuteChip<Fr, <Fr as Hashable>::SpecType, 3, 2>, const K: u32>(name: &str, c: &mut Criterion) where
PC::Config: Sync,{
    // define prover and verifier names
    let prover_name = "Measure prover time in ".to_owned() + name;
    let verifier_name = "Measure verifier time in ".to_owned() + name;
    // set params for protocol
    let params_path = format!("./benches/data/params_aggregate{}", K);

    let params = ParamsKZG::<Bn256>::setup(K, OsRng);
    let mut buf = Vec::new();
    params.write(&mut buf).expect("Failed to write params");
    write_to_file(&params_path, &buf);

    let params_fs = File::open(params_path).expect("Failed to load params");
    let params =
        ParamsKZG::read::<_>(&mut BufReader::new(params_fs)).expect("Failed to read params");

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

        let circuit: CommitAndAggregationCircuit<PC> =
            CommitAndAggregationCircuit::<PC>::new(hashed.clone(), partial_keys, aggregated_key, n);
        // combined_limbs.extend(combined_partial_limbs);
        combined_limbs.extend(hashed.clone());

        for value in hashed.clone() {
            println!("HASHED: {:?}", value);
        }

        let public_inputs = [combined_limbs.as_slice()]; // aggregated key & hash of partial keys


    // write verifying key
    let vk_path = format!("./benches/data/vk_aggregate{}", K);

    let vk = keygen_vk(&params, &circuit.clone()).expect("keygen_vk failed");
    let mut buf = Vec::new();
    match vk.write(&mut buf, SerdeFormat::RawBytes) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Error writing to buffer: {:?}", e);
        }
    }
    write_to_file(&vk_path, &buf);

    let vk_fs = File::open(vk_path).expect("Failed to load vk");
    let vk = VerifyingKey::<G1Affine>::read::<BufReader<File>, CommitAndAggregationCircuit<PC>>(
        &mut BufReader::new(vk_fs),
        SerdeFormat::RawBytes,
    )
    .expect("Failed to read vk");

    // write proving key
    let pk_path = format!("./benches/data/pk_aggregate{}", K);

    let pk = keygen_pk(&params, vk, &circuit.clone()).expect("keygen_pk failed");
    let mut buf = Vec::new();
    match pk.write(&mut buf, SerdeFormat::RawBytes) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Error writing to buffer: {:?}", e);
        }
    }
    write_to_file(&pk_path, &buf);

    let pk_fs = File::open(pk_path).expect("Failed to load pk");
    let pk = ProvingKey::<G1Affine>::read::<BufReader<File>, CommitAndAggregationCircuit<PC>>(
        &mut BufReader::new(pk_fs),
        SerdeFormat::RawBytes,
    )
    .expect("Failed to read pk");

    // benchmark the proof generation and store the proof
    let proof_path = format!("./benches/data/proof_aggregate{}", K);

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    c.bench_function(&prover_name, |b| {
        b.iter(|| {
            create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, _, _>(
                &params,
                &pk,
                &[circuit.clone()],
                &[public_inputs.as_slice()],
                &mut OsRng,
                &mut transcript,
            )
            .expect("proof generation failed")
        })
    });
    let proof: Vec<u8> = transcript.finalize();

    write_to_file(&proof_path, &proof);

    let mut proof_fs = File::open(proof_path).expect("Failed to load proof");
    let mut proof = Vec::<u8>::new();
    proof_fs
        .read_to_end(&mut proof)
        .expect("Fail to read proof");

    // benchmark the verification
    c.bench_function(&verifier_name, |b| {
        b.iter(|| {
            let accept = {
                let mut transcript: Blake2bRead<&[u8], _, Challenge255<_>> =
                    TranscriptReadBuffer::<_, G1Affine, _>::init(proof.as_slice());
                VerificationStrategy::<_, VerifierGWC<_>>::finalize(
                    verify_proof::<_, VerifierGWC<_>, _, _, _>(
                        params.verifier_params(),
                        pk.get_vk(),
                        AccumulatorStrategy::new(params.verifier_params()),
                        &[public_inputs.as_slice()],
                        &mut transcript,
                    )
                    .unwrap(),
                )
            };
            assert!(accept);
        });
    });
}

fn main() {
    let mut criterion = Criterion::default()
        .sample_size(10) // # of sample, >= 10
        .nresamples(10); // # of iteration

    let benches: Vec<Box<dyn Fn(&mut Criterion)>> =
        vec![Box::new(|c| bench_aggregate::<Pow5Chip<Fr, 3, 2>, 19>("skde aggregate", c))];

    for bench in benches {
        bench(&mut criterion);
    }
}