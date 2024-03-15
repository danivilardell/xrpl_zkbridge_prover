# XRPL zkBridge

This repo provies the necessary tools and instruction to generate a proof for the XRPL light client verification. This light client verification for one block involves the following:
1. Verify 35 secp256k1 ecdsa signatures against the XRPL validator's public key.
2. Verify the half sha512 computation that is later signed by the validators(not yet implemented).

## Built With

* [Circom](https://docs.circom.io): Generates R1CS and provides witness generation file.
* [Nova](https://github.com/microsoft/Nova): Folds secp256 ecdsa relaxed R1CS instances provided by Circom
* [Nova-Scotia](https://github.com/nalinbhardwaj/Nova-Scotia): Middleware to take generated output of the Circom compiler (R1CS constraints and generated witnesses) and use them with Nova as a prover

<!-- GETTING STARTED -->
## Getting Started



### Prerequisites

Below is a list of all the tools needed to generate the proof.

  ```sh
#Install basic modules
sudo apt update
sudo apt install gcc
sudo apt install nlohmann-json3-dev
sudo apt install libgmp-dev
sudo apt install nasm
sudo apt install npm

#Install rust
curl https://sh.rustup.rs -sSf | sh

#Install circom
git clone https://github.com/iden3/circom.git
cargo build --release #in repo
cargo install --path circom

#Install circomlib
npm i circomlib

#Increase V8 memory
export NODE_OPTIONS="--max-old-space-size=<size>"
  ```

### Installation

Below are the instructions needed to generate the proof. (This instruction set will work on 64 bit (x86) machines, if you are running M1 or M2, you will have to use the `verify_js` and `wasm` file for the witness generation, which is much slower that the `cpp` option.

1. Clone the repo that contains the circom circuit
   ```sh
   git clone https://github.com/danivilardell/circom-ecdsa.git
   ```
2. Download a Powers of Tau file with `2^20` and `2^21` constraints and copy it into the `circom-ecdsa/circuits` subdirectory of the project by running in that directory
   ```sh
   wget https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_20.ptau -O pot20_final.ptau
   wget https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_21.ptau -O pot21_final.ptau
   ```
3. In that repo generate the R1CS and witness generation files by running in the folder `circom-ecdsa/scripts/verify`
   ```sh
   circom "$CIRCUIT_NAME".circom --r1cs --wasm --sym --c --wat --output "$BUILD_DIR"  --prime vesta
   ```
4. Create the witness generation file by running `make` in the `circom-ecdsa/build/verify/verify_cpp/` subdirectory.
5. Clone this repo
   ```sh
   git clone https://github.com/danivilardell/xrpl_zkbridge_prover.git
   ```
6. Move the file `circom-ecdsa/build/verify/verify.r1cs` and folder `circom-ecdsa/build/verify/verify_cpp` into the `xrpl_zkbridge_prover/testing_nova/src/testing_files` subdirectory.
7. Now in `xrpl_zkbridge_prover/testing_nova/src` generate the recursive proof via
   ```sh
   cargo run
   ```

## Benchmark results
We can see here some benchmarking results for the generation of the proof using a c6a.4xlarge 64 bit (x86) machine.
  
|                              | Time          |
| -------------                | ------------- |
| Generate R1CS                | 48s           |
| Load R1CS file               | 19s           |
| Generate public parameters   | 1030s         |
| Create Folded instance       | 45s/instance  |
| Generate final proof         | 847s          |

So for 35 signatures, proof generation would take around 40 minutes, taking into account that the public parameters can be precomputed and we would only need to fold the instances and generate the final proof.
