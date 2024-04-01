use nova_scotia::{circom::reader::load_r1cs, FileLocation, create_public_params, create_recursive_circuit, F, S};
use std::{collections::HashMap, env::current_dir, time::Instant};
use nova_snark::{CompressedSNARK, PublicParams};
use serde_json::json;
use std::io::{Write, Read};
use serde_json::Value;
use std::fs::File;
use serde::{Serialize, Deserialize};


fn _compress_data(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn _decompress_data(data: &[u8]) -> Vec<u8> {
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).unwrap();
    decompressed
}

#[derive(Serialize, Deserialize, Debug)]
struct Witness {
    r: [String; 4],
    s: [String; 4],
    mghash: [String; 4],
    pubkey: [[String; 4]; 2],
}

fn main() {

    let iteration_count = 2;
    let root = current_dir().unwrap();

    // The cycle of curves we use, can be any cycle supported by Nova
    type G1 = pasta_curves::pallas::Point;
    type G2 = pasta_curves::vesta::Point;

    let mut private_inputs = Vec::new();

    let input_json_path = "./src/testing_files/input_data.json";
    let mut input_json_file = File::open(input_json_path).expect("Failed to open file");

    // Read the file contents into a string
    let mut input_json_string = String::new();
    input_json_file.read_to_string(&mut input_json_string)
        .expect("Failed to read file");

    // Parse the JSON string into a serde_json::Value
    let input_json: Value = serde_json::from_str(&input_json_string).expect("Failed to parse JSON");
    let datas: Vec<Witness> = serde_json::from_str(&input_json_string).unwrap();

    println!("Input JSON: {:?}", input_json);

    for wtns in datas {
        let mut private_input = HashMap::new();
        private_input.insert("r".to_string(), json!(wtns.r));
        private_input.insert("s".to_string(), json!(wtns.s));
        private_input.insert("msghash".to_string(), json!(wtns.mghash));
        private_input.insert("pubkey".to_string(), json!(wtns.pubkey));
        private_inputs.push(private_input);
    }

    println!("Private inputs: {:?}", private_inputs);

    let circuit_file = root.join("/Users/danielvilardellregue/Projects/xrpl_zkbridge_prover/ecdsa_nova/src/testing_files/verify.r1cs");
    let witness_generator_file =
        root.join("/Users/danielvilardellregue/Projects/xrpl_zkbridge_prover/ecdsa_nova/src/testing_files/verify_js/verify.wasm");

    let now = Instant::now();
    println!("Loading R1CS file...");
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::PathBuf(circuit_file)); // loads R1CS file into memory

    println!("R1CS file loaded in {:?}", now.elapsed());
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
    

    let start_public_input = [F::<G1>::from(0)];

    let recursive_snark = create_recursive_circuit(
        FileLocation::PathBuf(witness_generator_file.clone()),
        r1cs.clone(),
        private_inputs,
        start_public_input.to_vec(),
        &pp,
    )
    .unwrap();
    println!("RecursiveSNARK creation took {:?}", start.elapsed());


    // verify the recursive SNARK
    println!("Verifying a RecursiveSNARK...");
    let start = Instant::now();
    let res = recursive_snark.verify(&pp, iteration_count, &start_public_input, &[F::<G2>::from(0)]);
    println!(
        "RecursiveSNARK::verify: {:?}, took {:?}",
        res,
        start.elapsed()
    );
    assert!(res.is_ok());

    // produce a compressed SNARK
    println!("Generating a CompressedSNARK using Spartan with IPA-PC...");
    let start = Instant::now();

    let (pk, vk) = CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::setup(&pp).unwrap();
    let res = CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::prove(&pp, &pk, &recursive_snark);
    println!(
        "CompressedSNARK::prove: {:?}, took {:?}",
        res.is_ok(),
        start.elapsed()
    );
    assert!(res.is_ok());
    let compressed_snark = res.unwrap();

    // verify the compressed SNARK
    println!("Verifying a CompressedSNARK...");
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