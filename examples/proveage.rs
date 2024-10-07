use std::time::Instant;

use bellpepper::gadgets::multipack::{bytes_to_bits, compute_multipacking};
use clap::Command;
use flate2::{write::ZlibEncoder, Compression};
use image::{self};
use nova_aadhaar_qr::{
    circuit::{AadhaarAgeProofCircuit, OP_RSA_LAST, OP_SHA256_FIRST},
    poseidon::AadhaarIOHasher,
    qr::parse_aadhaar_qr_data,
    rsa::BIGNAT_NUM_LIMBS,
    sha256::{sha256_initial_digest_scalars, sha256_scalars_to_digest},
};
use nova_snark::{
    provider::{PallasEngine, VestaEngine},
    traits::{circuit::TrivialCircuit, snark::RelaxedR1CSSNARKTrait, Engine},
    CompressedSNARK, PublicParams, RecursiveSNARK,
};
use num_bigint::BigInt;
use sha2::{Digest, Sha256};
use zlib_rs::{
    inflate::{uncompress_slice, InflateConfig},
    ReturnCode,
};

fn main() {
    let cmd = Command::new("Aadhaar-based Proof of 18+ Age")
        .bin_name("proveage")
        .arg(
            clap::Arg::new("aadhaar_qrcode_image")
                .value_name("Aadhaar QR code image file")
                .required(true),
        )
        .arg(
            clap::Arg::new("current_date")
                .value_name("Current date in DD-MM-YYYY format")
                .required(true),
        )
        .after_help("The proveage command proves that the Aadhaar holder is 18+");

    let m = cmd.get_matches();
    let fname = m.get_one::<String>("aadhaar_qrcode_image").unwrap();
    let current_date_str = m.get_one::<String>("current_date").unwrap();
    let current_date_bytes: &[u8; 10] = current_date_str.as_bytes().try_into().unwrap();

    let img = image::open(fname).unwrap().to_luma8();
    // Prepare for detection
    let mut img = rqrr::PreparedImage::prepare(img);
    // Search for grids, without decoding
    let grids = img.detect_grids();
    assert_eq!(grids.len(), 1);
    // Decode the grid
    let (_, content) = grids[0].decode().unwrap();

    let content_bytes = content.as_bytes();
    let qr_int = BigInt::parse_bytes(content_bytes, 10).unwrap();
    let (_, qr_int_bytes) = qr_int.to_bytes_be();

    let mut output = [0; 1 << 13];
    let config = InflateConfig { window_bits: 31 };
    let (decompressed_qr_bytes, ret) = uncompress_slice(&mut output, &qr_int_bytes, config);
    assert_eq!(ret, ReturnCode::Ok);
    // println!("{:?}", String::from_utf8_lossy(decompressed_qr_bytes));

    type E1 = PallasEngine;
    type E2 = VestaEngine;
    type EE1 = nova_snark::provider::ipa_pc::EvaluationEngine<E1>;
    type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
    type S1 = nova_snark::spartan::zksnark::RelaxedR1CSSNARK<E1, EE1>;
    type S2 = nova_snark::spartan::zksnark::RelaxedR1CSSNARK<E2, EE2>;
    type C1 = AadhaarAgeProofCircuit<<E1 as Engine>::Scalar>;
    type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;
    let circuit_primary: C1 = AadhaarAgeProofCircuit::default();
    let circuit_secondary: C2 = TrivialCircuit::default();

    let param_gen_timer = Instant::now();
    println!("Producing public parameters...");
    let pp = PublicParams::<E1, E2, C1, C2>::setup(
        &circuit_primary,
        &circuit_secondary,
        &*S1::ck_floor(),
        &*S2::ck_floor(),
    )
    .unwrap();

    let param_gen_time = param_gen_timer.elapsed();
    println!("PublicParams::setup, took {:?} ", param_gen_time);

    println!(
        "Number of constraints per step (primary circuit): {}",
        pp.num_constraints().0
    );
    println!(
        "Number of constraints per step (secondary circuit): {}",
        pp.num_constraints().1
    );
    println!(
        "Number of variables per step (primary circuit): {}",
        pp.num_variables().0
    );
    println!(
        "Number of variables per step (secondary circuit): {}",
        pp.num_variables().1
    );

    let res = parse_aadhaar_qr_data(decompressed_qr_bytes.to_vec());
    if !res.is_ok() {
        panic!("Error parsing Aadhaar QR code bytes")
    }
    let aadhaar_qr_data = res.unwrap();

    let primary_circuit_sequence = C1::new_state_sequence(&aadhaar_qr_data);

    let sha256_iv = sha256_initial_digest_scalars::<<E1 as Engine>::Scalar>();
    let initial_opcode = <E1 as Engine>::Scalar::from(OP_SHA256_FIRST);

    let aadhaar_io_hasher =
        AadhaarIOHasher::<<E1 as Engine>::Scalar>::new(2 + BIGNAT_NUM_LIMBS as u32);
    let mut initial_io_values = sha256_iv;
    initial_io_values.extend_from_slice(&[<E1 as Engine>::Scalar::zero(); BIGNAT_NUM_LIMBS]);
    let initial_io_hash = aadhaar_io_hasher.hash(&initial_io_values);

    let current_date_bits = bytes_to_bits(current_date_bytes);
    let current_date_scalars = compute_multipacking::<<E1 as Engine>::Scalar>(&current_date_bits);
    assert_eq!(current_date_scalars.len(), 1);
    let current_date_scalar = current_date_scalars[0];

    // The last scalar corresponds to the current date
    let z0_primary = vec![initial_opcode, initial_io_hash, current_date_scalar];

    let z0_secondary = vec![<E2 as Engine>::Scalar::zero()];

    let proof_gen_timer = Instant::now();
    // produce a recursive SNARK
    println!("Generating a RecursiveSNARK...");
    let mut recursive_snark: RecursiveSNARK<E1, E2, C1, C2> =
        RecursiveSNARK::<E1, E2, C1, C2>::new(
            &pp,
            &primary_circuit_sequence[0],
            &circuit_secondary,
            &z0_primary,
            &z0_secondary,
        )
        .unwrap();

    let start = Instant::now();
    for (i, circuit_primary) in primary_circuit_sequence.iter().enumerate() {
        let step_start = Instant::now();
        let res = recursive_snark.prove_step(&pp, circuit_primary, &circuit_secondary);
        assert!(res.is_ok());
        println!(
            "RecursiveSNARK::prove_step {}: {:?}, took {:?} ",
            i,
            res.is_ok(),
            step_start.elapsed()
        );
    }
    println!(
        "Total time taken by RecursiveSNARK::prove_steps: {:?}",
        start.elapsed()
    );

    // verify the recursive SNARK
    println!("Verifying a RecursiveSNARK...");
    let start = Instant::now();
    let num_steps = primary_circuit_sequence.len();
    let res = recursive_snark.verify(&pp, num_steps, &z0_primary, &z0_secondary);
    println!(
        "RecursiveSNARK::verify: {:?}, took {:?}",
        res.is_ok(),
        start.elapsed()
    );
    assert!(res.is_ok());

    // produce a compressed SNARK
    println!("Generating a CompressedSNARK using Spartan with IPA-PC...");
    let (pk, vk) = CompressedSNARK::<_, _, _, _, S1, S2>::setup(&pp).unwrap();

    let start = Instant::now();

    let res = CompressedSNARK::<_, _, _, _, S1, S2>::prove(&pp, &pk, &recursive_snark);
    println!(
        "CompressedSNARK::prove: {:?}, took {:?}",
        res.is_ok(),
        start.elapsed()
    );
    assert!(res.is_ok());

    let proving_time = proof_gen_timer.elapsed();
    println!("Total proving time is {:?}", proving_time);

    let compressed_snark = res.unwrap();

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    bincode::serialize_into(&mut encoder, &compressed_snark).unwrap();
    let compressed_snark_encoded = encoder.finish().unwrap();
    println!(
        "CompressedSNARK::len {:?} bytes",
        compressed_snark_encoded.len()
    );

    // verify the compressed SNARK
    println!("Verifying a CompressedSNARK...");
    let start = Instant::now();
    let res = compressed_snark.verify(&vk, num_steps, &z0_primary, &z0_secondary);
    let verification_time = start.elapsed();
    println!(
        "CompressedSNARK::verify: {:?}, took {:?}",
        res.is_ok(),
        verification_time,
    );
    assert!(res.is_ok());
    println!("=========================================================");
    println!("Public parameters generation time: {:?} ", param_gen_time);
    println!(
        "Total proving time (excl pp generation): {:?}",
        proving_time
    );
    println!("Total verification time: {:?}", verification_time);

    println!("=========================================================");

    let final_outputs = res.unwrap().0;

    let final_opcode = final_outputs[0];
    assert_eq!(final_opcode, <E1 as Engine>::Scalar::from(OP_RSA_LAST + 1));

    let calculated_revealed_data_hash =
        sha256_scalars_to_digest(final_outputs[1..].try_into().unwrap());
    println!(
        "Calculated revealed data hash  = {}",
        hex::encode(calculated_revealed_data_hash)
    );

    let mut hasher = Sha256::new();
    hasher.update(aadhaar_qr_data.signed_data);
    let expected_revealed_data_hash: [u8; 32] = hasher.finalize().try_into().unwrap();
    println!(
        "Expected revealed data hash    = {}",
        hex::encode(expected_revealed_data_hash)
    );
}
