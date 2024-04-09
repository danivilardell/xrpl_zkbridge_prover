package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
)

type Signatures struct {
	R       string `json:"r"`
	S       string `json:"s"`
	MsgHash string `json:"msghash"`
	X       string `json:"x"`
	Y       string `json:"y"`
}

func TestEcdsaSHA256(t *testing.T) {

	fileContent, _ := ioutil.ReadFile("input.json")
	var signatures []Signatures
	json.Unmarshal(fileContent, &signatures)

	cs, _ := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{})
	fmt.Println("compiled")
	pk, vk, _ := groth16.Setup(cs)
	fmt.Println("setup")

	proofs := make([]groth16.Proof, len(signatures))
	assignments := make([]EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr], len(signatures))
	for i := 0; i < len(signatures); i++ {
		fmt.Println("Generating proof #", i)
		r, _ := new(big.Int).SetString(signatures[i].R, 10)
		s, _ := new(big.Int).SetString(signatures[i].S, 10)
		hash, _ := new(big.Int).SetString(signatures[i].MsgHash, 10)
		x, _ := new(big.Int).SetString(signatures[i].X, 10)
		y, _ := new(big.Int).SetString(signatures[i].Y, 10)

		circuit := EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
		assignments[i] = EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			Sig: ecdsa.Signature[emulated.Secp256k1Fr]{
				R: emulated.ValueOf[emulated.Secp256k1Fr](r),
				S: emulated.ValueOf[emulated.Secp256k1Fr](s),
			},
			Msg: emulated.ValueOf[emulated.Secp256k1Fr](hash),
			Pub: ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](x),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](y),
			},
		}

		assert := test.NewAssert(t)
		err := test.IsSolved(&circuit, &assignments[i], ecc.BN254.ScalarField())
		assert.NoError(err)
		witness, _ := frontend.NewWitness(&assignments[i], ecc.BLS12_377.ScalarField())

		proofs[i], _ = groth16.Prove(cs, pk, witness)

		public_witness, _ := frontend.NewWitness(&assignments[i], ecc.BLS12_377.ScalarField(), frontend.PublicOnly())

		err = groth16.Verify(proofs[i], vk, public_witness)
		assert.NoError(err)
		fmt.Println("Proof #", i, "verified")
	}

	foldedProof, err := groth16.FoldProofs(proofs, vk)
	if err != nil {
		fmt.Println(err)
	}

	publicWitnesses := make([]witness.Witness, len(signatures))
	for i := 0; i < len(signatures); i++ {
		publicWitness, _ := frontend.NewWitness(&assignments[i], ecc.BLS12_377.ScalarField(), frontend.PublicOnly())
		publicWitnesses[i] = publicWitness
	}

	foldingParameters, err := groth16.GetFoldingParameters(proofs, vk, publicWitnesses)
	if err != nil {
		fmt.Println(err)
	}

	err = groth16.VerifyFolded(foldedProof, foldingParameters, vk, publicWitnesses, proofs)
	if err != nil {
		fmt.Println(err)
	}
}

/*
[{ not working
    "r": "115158035811458795053925695987053306149659527984642617847225020470566121318459",
    "s": "57103074896689946840487982608739427129233226707186500617681853919408460815967",
    "msghash": "24902586981639429803573318083869284215927205872316806891403959192641726669584",
    "x": "103815691426097406341991065078537543982391910004522962722260281408613359390497",
    "y": "56779485566969834522538136638522167250310292249136415837314019429696078506005"
}, { working
    "r": "73594631905943291163701986304973238407770252851585626113934464576033007799747",
    "s": "54058322171983755044315026093546074754521982724771458969212452594662085061609",
    "msghash": "97213057300499822318689965482938317876640079446865418112811458500406248320049",
    "x": "33989513386018865173992657751408217788581614547339808612317570988827410895130",
    "y": "21894368923015667079551539032089492490711045078734833251165268866778154879055"
}, {
    "r": "51267089888161287470259272463806669953119604246530609511956224202751445748576",
    "s": "2229540704871423853782585452726926087377000100820748085294011597168450574332",
    "msghash": "38546092374991721217246043307484672742789142118107538269990876460868813755311",
    "x": "65658861218218885799203097583380177421097521294761401825093290465621268319218",
    "y": "69070155456330330122152131783241895694134035115506462463369658058256693383171"
}, {
    "r": "69778548619626042458803500309303121788566986934233117360777236174169017091276",
    "s": "3057371949936031690770935916964166420833348847566862120927401219003400031763",
    "msghash": "45102417046393905891551167062982157102030951312937441824019887732232079309162",
    "x": "90027989163329197062915102582461117659664334334972072170619213303861485342181",
    "y": "9756066324414412440687039474848397421682112417162455279808556286062022939851"
}, {
    "r": "13704032906605928179322307417732057874765754161698451864509836453044728539598",
    "s": "52845530819045355944437577856406485480656638295305672028216887019154667211243",
    "msghash": "41652371597962231488164129190216091083454015879418402790672320970555492785665",
    "x": "37735139328221678307479378687547575844283928405342328589980569703016641639813",
    "y": "37196207109562352685945057758932546935627032950462947234851204137422003674110"
}]
*/
