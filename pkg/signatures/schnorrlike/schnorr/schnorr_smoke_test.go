package vanilla_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
	vanilla "github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/schnorr"
)

func _[
	G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S],
]() {
	var (
		_ signatures.Scheme[
			*vanilla.PrivateKey[G, S], *vanilla.PublicKey[G, S],
			vanilla.Message, *vanilla.Signature[G, S],
			*vanilla.KeyGenerator[G, S], *vanilla.Signer[G, S], *vanilla.Verifier[G, S],
		] = (*vanilla.Scheme[G, S])(nil)
	)
}
