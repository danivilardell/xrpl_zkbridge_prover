use nova_scotia::{circom::reader::load_r1cs, FileLocation, create_public_params, create_recursive_circuit, F, S};
use std::{collections::HashMap, env::current_dir, time::Instant};
use nova_snark::{CompressedSNARK, PublicParams};
use serde_json::json;
use std::io::{Write, Read};
use std::fs::File;
use serde::{Serialize, Deserialize};
use num_bigint::BigUint;
use num_traits::Num;

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

fn decompress_public_key(public_key_hex: String) -> (BigUint, BigUint) {
    // Convert the hexadecimal public key to bytes
    let public_key_bytes = hex::decode(public_key_hex).expect("Failed to decode hex");

    // Extract the x-coordinate from the public key bytes (excluding the prefix byte)
    let x_hex = &public_key_bytes[1..33];

    // Convert the x-coordinate to a big integer
    let x_int = BigUint::from_bytes_be(x_hex);

    let p: BigUint = BigUint::from(2u32).pow(256) - BigUint::from(2u32).pow(32) - BigUint::from(2u32).pow(10) + BigUint::from(2u32).pow(6) - BigUint::from(2u32).pow(4) - BigUint::from(1u32);
    let exp = (&p + BigUint::from(1u32)) / BigUint::from(4u32);
    let y0 = x_int.modpow(&BigUint::from(3u32), &p) + BigUint::from(7u32);
    let y0 = y0.modpow(&exp, &p);

    let prefix_byte = public_key_bytes[0];
    let y_int = if prefix_byte == 0x03 {
        y0.clone()
    } else if prefix_byte == 0x02 {
        &p - &y0
    } else {
        panic!("Invalid prefix byte")
    };

    (x_int, y_int)
}

fn decompress_signature(sig: String) -> (BigUint, BigUint) {
    let has_zeros_r = &sig[6..8];

    let r: BigUint;
    let s: BigUint;
    if has_zeros_r == "20" {
        r = BigUint::from_str_radix(&sig[8..72], 16).unwrap();
        let has_zeros_s = &sig[74..76];

        if has_zeros_s == "20" {
            s = BigUint::from_str_radix(&sig[76..140], 16).unwrap();
        } else {
            s = BigUint::from_str_radix(&sig[78..142], 16).unwrap();
        }
        
    } else {
        r = BigUint::from_str_radix(&sig[10..74], 16).unwrap();
        let has_zeros_s = &sig[76..78];

        if has_zeros_s == "20" {
            s = BigUint::from_str_radix(&sig[78..142], 16).unwrap();
        } else {
            s = BigUint::from_str_radix(&sig[80..144], 16).unwrap();
        }
    }

    return (r, s);
}

fn bigint_to_array(n: u64, k: u64, x: BigUint) -> Vec<String> {
    let modulus = BigUint::from(1u32) << n;
    let mut ret = Vec::new();
    let mut x_temp = x.clone();
    
    for _ in 0..k {
        ret.push(format!("{}", &x_temp % &modulus));
        x_temp /= &modulus;
    }
    
    ret
}

#[derive(Serialize, Deserialize, Debug)]
struct Witness {
    sig: String,
    mghash: String,
    pubkey: String,
}

fn main() {

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
    let datas: Vec<Witness> = serde_json::from_str(&input_json_string).unwrap();
    let iteration_count = datas.len(); // Number of signatures to fold

    for wtns in datas {
        // Find the uncompressed 2-point representation
        let uncompressed_public_key = decompress_public_key(wtns.pubkey);
    
        let x = bigint_to_array(64, 4, uncompressed_public_key.0);
        let y = bigint_to_array(64, 4, uncompressed_public_key.1);

        let hash = bigint_to_array(64, 4, BigUint::from_str_radix(wtns.mghash.as_str(), 16).unwrap());

        let sig = decompress_signature(wtns.sig);
        let r = bigint_to_array(64, 4, sig.0);
        let s = bigint_to_array(64, 4, sig.1);

        let mut private_input = HashMap::new();
        private_input.insert("r".to_string(), json!(r));
        private_input.insert("s".to_string(), json!(s));
        private_input.insert("msghash".to_string(), json!(hash));
        private_input.insert("pubkey".to_string(), json!([x, y]));
        private_inputs.push(private_input);
    }


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