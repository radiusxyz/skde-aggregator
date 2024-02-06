use halo2wrong::curves::bn256::Fr;
use halo2wrong::halo2::halo2curves::bn256::{Bn256, G1Affine};

use halo2wrong::halo2::{
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
use skde::{
    aggregate, AggregateCircuit, DecomposedExtractionKey, ExtractionKey, BITS_LEN,
    MAX_SEQUENCER_NUMBER,
};

use num_bigint::{BigUint, RandomBits};
use rand::{thread_rng, Rng};
use rand_core::OsRng;
// use core::slice::SlicePattern;
use std::{
    fs::File,
    io::{BufReader, Read, Write},
    marker::PhantomData,
    path::Path,
};
// bench-mark tool
use criterion::Criterion;

fn bench_aggregate<const K: u32>(name: &str, c: &mut Criterion) {
    // define prover and verifier names
    let prover_name = "Measure prover time in ".to_owned() + name;
    let verifier_name = "Measure verifier time in ".to_owned() + name;
    // set params for protocol
    let params_path = "./benches/data/params_aggregate".to_owned() + &K.to_string();
    let params_path = Path::new(&params_path);
    if File::open(params_path).is_err() {
        let params = ParamsKZG::<Bn256>::setup(K, OsRng);
        let mut buf = Vec::new();
        params.write(&mut buf).expect("Failed to write params");
        let mut file = File::create(params_path).expect("Failed to create params");
        file.write_all(&buf[..])
            .expect("Failed to write params to file");
    }
    let params_fs = File::open(params_path).expect("Failed to load params");
    let params =
        ParamsKZG::read::<_>(&mut BufReader::new(params_fs)).expect("Failed to read params");

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

    // set public input
    let combined_partial_limbs: Vec<Fr> =
        aggregate::chip::ExtractionKey::decompose_and_combine_all_partial_keys(
            partial_keys.clone(),
        );

    let decomposed_extraction_key: DecomposedExtractionKey<Fr> =
        aggregate::chip::ExtractionKey::decompose_extraction_key(&aggregated_key.clone());
    let mut combined_limbs = decomposed_extraction_key.combine_limbs();

    combined_limbs.extend(combined_partial_limbs);

    let public_inputs = [combined_limbs.as_slice()];

    let circuit = AggregateCircuit::<Fr> {
        partial_keys,
        aggregated_key,
        n,
        n_square,
        _f: PhantomData,
    };
    

    // write verifying key
    let vk_path = "./benches/data/vk_aggregate".to_owned() + &K.to_string();
    if File::open(&vk_path).is_err() {
        let vk = keygen_vk(&params, &circuit.clone()).expect("keygen_vk failed");
        let mut buf = Vec::new();
        let _ = vk.write(&mut buf, SerdeFormat::RawBytes);
        let mut file = File::create(&vk_path).expect("Failed to create vk");
        file.write_all(&buf[..])
            .expect("Failed to write vk to file");
    }
    let vk_fs = File::open(vk_path).expect("Failed to load vk");
    let vk = VerifyingKey::<G1Affine>::read::<BufReader<File>, AggregateCircuit<Fr>>(
        &mut BufReader::new(vk_fs),
        SerdeFormat::RawBytes,
    )
    .expect("Failed to read vk");

    // write proving key
    let pk_path = "./benches/data/pk_aggregate".to_owned() + &K.to_string();
    if File::open(&pk_path).is_err() {
        let pk = keygen_pk(&params, vk, &circuit.clone()).expect("keygen_pk failed");
        let mut buf = Vec::new();
        let _ = pk.write(&mut buf, SerdeFormat::RawBytes);
        let mut file = File::create(&pk_path).expect("Failed to create pk");
        file.write_all(&buf[..])
            .expect("Failed to write pk to file");
    }
    let pk_fs = File::open(pk_path).expect("Failed to load pk");
    let pk = ProvingKey::<G1Affine>::read::<BufReader<File>, AggregateCircuit<Fr>>(
        &mut BufReader::new(pk_fs),
        SerdeFormat::RawBytes,
    )
    .expect("Failed to read pk");

    // benchmark the proof generation and store the proof
    let proof_path = "./benches/data/proof_aggregate".to_owned() + &K.to_string();
    let proof_path = Path::new(&proof_path);
    if File::open(proof_path).is_err() {
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

        let mut file = File::create(proof_path).expect("Failed to create proof");
        file.write_all(&proof[..]).expect("Failed to write proof");
    }
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

// fn criterion_benchmark(c: &mut Criterion) {
//     bench_aggregate::<20>("skde aggregate", c);
// }

// criterion_group!(benches, criterion_benchmark);
// criterion_main!(benches);

fn main() {
    let mut criterion = Criterion::default()
        .sample_size(10) // # of sample, >= 10
        .nresamples(10); // # of iteration

    let benches: Vec<Box<dyn Fn(&mut Criterion)>> =
        vec![Box::new(|c| bench_aggregate::<16>("skde aggregate", c))];

    for bench in benches {
        bench(&mut criterion);
    }
}
