package ecdsa_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

func _[
	P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S],
]() {
	var (
		_ signatures.Scheme[
			*ecdsa.PrivateKey[P, B, S], *ecdsa.PublicKey[P, B, S],
			[]byte, *ecdsa.Signature[S],
			*ecdsa.KeyGenerator[P, B, S], *ecdsa.Signer[P, B, S], *ecdsa.Verifier[P, B, S],
		] = (*ecdsa.Scheme[P, B, S])(nil)
	)
}
