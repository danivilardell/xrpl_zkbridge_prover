use nova_scotia::{circom::reader::load_r1cs, FileLocation, create_public_params, create_recursive_circuit, F};
use std::{collections::HashMap, env::current_dir, time::Instant};
use nova_snark::PublicParams;
use serde_json::json;
use std::fs::File;
use std::io::{Write, Read};
use std::io;

fn compress_data(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn decompress_data(data: &[u8]) -> Vec<u8> {
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).unwrap();
    decompressed
}

fn main() {

    let iteration_count = 2;
    let root = current_dir().unwrap();

    // The cycle of curves we use, can be any cycle supported by Nova
    type G1 = pasta_curves::pallas::Point;
    type G2 = pasta_curves::vesta::Point;

    let circuit_file = root.join("/Users/danielvilardellregue/Projects/xrpl_zkbridge_prover/testing_nova/src/testing_files/verify.r1cs");
    let witness_generator_file =
        root.join("/Users/danielvilardellregue/Projects/xrpl_zkbridge_prover/testing_nova/src/testing_files/verify_js/verify.wasm");

    let mut now = Instant::now();
    println!("Loading R1CS file...");
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::PathBuf(circuit_file)); // loads R1CS file into memory

    println!("R1CS file loaded in {:?}", now.elapsed());
    println!("Creating public parameters...");
    let pp: PublicParams<G1, G2, _, _> = create_public_params(r1cs.clone());
    println!("Public parameters created in {:?}", now.elapsed());

    //let serialized = serde_json::to_string(&pp).unwrap();
    //let mut file = File::create("/Users/danielvilardellregue/Projects/xrpl_zkbridge_prover/testing_nova/src/testing_files/public_params.pp").unwrap();
    //file.write_all(serialized.as_bytes()).unwrap();

    /* 
    now = Instant::now();
    // Serialize the public parameters
    let serialized = bincode::serialize(&pp).unwrap(); // Assuming you're using Bincode
    // Compress the serialized data
    let compressed = compress_data(&serialized); // Define a function to compress data

    // Write the compressed data to the file
    let mut file = File::create("/Users/danielvilardellregue/Projects/xrpl_zkbridge_prover/testing_nova/src/testing_files/public_params.pp").unwrap();
    file.write_all(&compressed).unwrap();
    println!("Public parameters stored to file in {:?}", now.elapsed());
    */

    /*now = Instant::now();
    let mut file = File::open("/Users/danielvilardellregue/Projects/xrpl_zkbridge_prover/testing_nova/src/testing_files/public_params.pp").unwrap();
    let mut compressed_data = Vec::new();
    file.read_to_end(&mut compressed_data).unwrap();
    println!("Public parameters loaded from file in {:?}", now.elapsed());

    now = Instant::now();
    // Decompress the data
    let decompressed_data = decompress_data(&compressed_data); // Define a function to decompress data
    println!("Public parameters decompressed in {:?}", now.elapsed());

    now = Instant::now();
    // Deserialize the data
    let pp: PublicParams<G1, G2, _, _> = bincode::deserialize(&decompressed_data).unwrap(); // Assuming you're using Bincode
    println!("Public parameters deserialized in {:?}", now.elapsed());*/

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
        private_input.insert("r".to_string(), json!([11878389131962663075u64, 9922462056030557342u64, 6756396965793543634u64, 12446269625364732260u64]));
        private_input.insert("s".to_string(), json!([18433728439776304144u64, 9948993517021512060u64, 8616204783675899344u64, 12630110559440107129u64]));
        private_input.insert("msghash".to_string(), json!([7828219513492386041u64, 3988479630986735061u64, 17828618373474417767u64, 7725776341465200115u64]));
        private_input.insert("pubkey".to_string(), json!([[15936664623177566288u64, 3250397285527463885u64, 12867682233480762946u64, 7876377878669208042u64], [17119974326854866418u64, 4804456518640350784u64, 12443422089272457229u64, 9048921188902050084u64]]));
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
