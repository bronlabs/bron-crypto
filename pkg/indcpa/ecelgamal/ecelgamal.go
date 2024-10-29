package ecelgamal

import "github.com/copperexchange/krypton-primitives/pkg/base/curves"

type PlainText = curves.Point
type Scalar = curves.Scalar
type Nonce = curves.Scalar
type CipherText struct {
	C1 curves.Point
	C2 curves.Point
}
