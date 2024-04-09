use nova_scotia::{F, circom::circuit::CircomCircuit};
use pasta_curves::{Ep, Eq, Fp, Fq};
use std::{time::Instant};
use nova_snark::{CompressedSNARK, traits::circuit::TrivialTestCircuit, spartan::snark::RelaxedR1CSSNARK, provider::ipa_pc::EvaluationEngine, VerifierKey};
use std::io::{Read};
use std::fs::File;

fn verify_proof(proof_file_path: String, vk_file_path: String) {
    type G1 = pasta_curves::pallas::Point;
    type G2 = pasta_curves::vesta::Point;
    
    let iteration_count = 10;
    let mut proof_file = File::open(proof_file_path).expect("Failed to open file");
    let mut compressed_snark_json = String::new();
    proof_file.read_to_string(&mut compressed_snark_json)
        .expect("Failed to read file");

    // Deserialize JSON string into a Person object
    let compressed_snark: CompressedSNARK<Ep, Eq, CircomCircuit<Fq>, TrivialTestCircuit<Fp>, RelaxedR1CSSNARK<Ep, EvaluationEngine<Ep>>, RelaxedR1CSSNARK<Eq, EvaluationEngine<Eq>>> = serde_json::from_str(&compressed_snark_json)
        .expect("Failed to deserialize JSON");

    let start = Instant::now();
    let mut vk_file = File::open(vk_file_path).expect("Failed to open file");
    let mut vk_json = String::new();
    vk_file.read_to_string(&mut vk_json)
        .expect("Failed to read file");
    
    // Deserialize JSON string into a Person object
    let vk: VerifierKey<Ep, Eq, CircomCircuit<Fq>, TrivialTestCircuit<Fp>, RelaxedR1CSSNARK<Ep, EvaluationEngine<Ep>>, RelaxedR1CSSNARK<Eq, EvaluationEngine<Eq>>> = serde_json::from_str(&vk_json)
        .expect("Failed to deserialize JSON");
    
    println!("vk loaded from file in {:?}", start.elapsed());

    let start_public_input = [F::<G1>::from(0)];

    let start = Instant::now();
    let res = compressed_snark.verify(
        &vk,
        iteration_count,
        start_public_input.to_vec(),
        [F::<G2>::from(0)].to_vec(),
    );
    println!(
        "CompressedSNARK::verify: {:?}, took {:?}",
        res.is_ok(),
        start.elapsed()
    );
    assert!(res.is_ok());
}

fn main() {
    verify_proof("proof".to_string(), "vk".to_string());
}
