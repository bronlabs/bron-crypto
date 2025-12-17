package hpke_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/hpke"
)

var ()

func _[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]]() {
	var (
		_ encryption.AEADBasedHybridScheme[
			*hpke.PrivateKey[S],
			*hpke.PublicKey[P, B, S],
			hpke.Message,
			hpke.Ciphertext,
			*hpke.Capsule[P, B, S],
			*hpke.KeyGenerator[P, B, S],
			*hpke.KEM[P, B, S],
			*hpke.DEM[P, B, S],
			*hpke.Encrypter[P, B, S],
			*hpke.Decrypter[P, B, S],
		] = (*hpke.Scheme[P, B, S])(nil)
	)
}
