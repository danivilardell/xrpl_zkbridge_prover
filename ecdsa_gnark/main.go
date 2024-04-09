package main

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/ecdsa"
)

type EcdsaCircuit[T, S emulated.FieldParams] struct {
	Sig ecdsa.Signature[S]
	Msg emulated.Element[S]
	Pub ecdsa.PublicKey[T, S]
}

func (c *EcdsaCircuit[T, S]) Define(api frontend.API) error {
	c.Pub.Verify(api, sw_emulated.GetCurveParams[T](), &c.Msg, &c.Sig)
	return nil
}
