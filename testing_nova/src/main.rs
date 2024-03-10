use nova_scotia::{circom::reader::load_r1cs, FileLocation, create_public_params, create_recursive_circuit, F};
use std::{collections::HashMap, env::current_dir, time::Instant};
use nova_snark::PublicParams;
use serde_json::json;

fn main() {

    let iteration_count = 5;
    let root = current_dir().unwrap();

    // The cycle of curves we use, can be any cycle supported by Nova
    type G1 = pasta_curves::pallas::Point;
    type G2 = pasta_curves::vesta::Point;

    let circuit_file = root.join("/Users/danielvilardellregue/Projects/ZKP_hackathon/xrpl_zkbridge_prover/testing_nova/src/testing_files/verify.r1cs");
    let witness_generator_file =
        root.join("/Users/danielvilardellregue/Projects/ZKP_hackathon/xrpl_zkbridge_prover/testing_nova/src/testing_files/verify_js/verify.wasm");

    let mut now = Instant::now();
    println!("Loading R1CS file...");
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::PathBuf(circuit_file)); // loads R1CS file into memory

    println!("R1CS file loaded in {:?}", now.elapsed());
    now = Instant::now();
    println!("Creating public parameters...");
    let pp: PublicParams<G1, G2, _, _> = create_public_params(r1cs.clone());
    println!("Public parameters created in {:?}", now.elapsed());

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

    println!("Creating a RecursiveSNARK...");
    let start = Instant::now();
    let mut private_inputs = Vec::new();

    for i in 0..iteration_count {
        let mut private_input = HashMap::new();
        private_input.insert("adder".to_string(), json!(i));
        private_inputs.push(private_input);
    }

    let start_public_input = [F::<G1>::from(0)];

    let mut recursive_snark = create_recursive_circuit(
        FileLocation::PathBuf(witness_generator_file.clone()),
        r1cs.clone(),
        private_inputs,
        start_public_input.to_vec(),
        &pp,
    )
    .unwrap();
    println!("RecursiveSNARK creation took {:?}", start.elapsed());

}
