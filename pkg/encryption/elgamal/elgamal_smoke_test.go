package elgamal_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/elgamal"
)

func _[E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]]() {
	var (
		_ encryption.GroupHomomorphicEncryptionKey[
			*elgamal.PublicKey[E, S],
			*elgamal.Plaintext[E, S], elgamal.FiniteCyclicGroup[E, S], E,
			*elgamal.Nonce[S], algebra.ZModLike[S], S,
			*elgamal.Ciphertext[E, S], *constructions.FiniteDirectPowerModule[elgamal.FiniteCyclicGroup[E, S], E, S], *constructions.FiniteDirectPowerModuleElement[E, S],
			S,
		] = (*elgamal.PublicKey[E, S])(nil)

		_ encryption.GroupHomomorphicDecryptionKey[
			*elgamal.PublicKey[E, S],
			*elgamal.SecretKey[E, S],
			*elgamal.Plaintext[E, S], elgamal.FiniteCyclicGroup[E, S], E,
			*elgamal.Nonce[S], algebra.ZModLike[S], S,
			*elgamal.Ciphertext[E, S], *constructions.FiniteDirectPowerModule[elgamal.FiniteCyclicGroup[E, S], E, S], *constructions.FiniteDirectPowerModuleElement[E, S],
			S,
		] = (*elgamal.SecretKey[E, S])(nil)
	)
}
