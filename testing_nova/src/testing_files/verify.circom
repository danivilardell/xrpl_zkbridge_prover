pragma circom 2.0.2;

include "../../circuits/ecdsa.circom";

component main {public [val]} = ECDSAVerifyNoPubkeyCheck(64, 4);
