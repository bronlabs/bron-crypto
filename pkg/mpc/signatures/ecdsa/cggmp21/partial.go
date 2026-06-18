package cggmp21

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
)

// PartialSignature is one party's CGGMP21 online ECDSA signing output.
type PartialSignature[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Gamma P `cbor:"gamma"`
	Sigma S `cbor:"sigma"`
}
