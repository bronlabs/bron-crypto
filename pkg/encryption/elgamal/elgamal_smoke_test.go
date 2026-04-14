package elgamal_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/elgamal"
	"github.com/fxamacker/cbor/v2"
)

func _[E elgamal.UnderlyingGroupElement[E, S], S algebra.UintLike[S]]() {
	var (
		_ encryption.PrivateKey[*elgamal.PrivateKey[E, S]]                                                            = (*elgamal.PrivateKey[E, S])(nil)
		_ encryption.PublicKey[*elgamal.PublicKey[E, S]]                                                              = (*elgamal.PublicKey[E, S])(nil)
		_ encryption.ReRandomisableCiphertext[*elgamal.Ciphertext[E, S], *elgamal.Nonce[S], *elgamal.PublicKey[E, S]] = (*elgamal.Ciphertext[E, S])(nil)
	)
	var (
		_ encryption.Scheme[
			*elgamal.PrivateKey[E, S], *elgamal.PublicKey[E, S], *elgamal.Plaintext[E, S], *elgamal.Ciphertext[E, S], *elgamal.Nonce[S],
			*elgamal.KeyGenerator[E, S], *elgamal.Encrypter[E, S], *elgamal.Decrypter[E, S],
		] = (*elgamal.Scheme[E, S])(nil)

		_ encryption.GroupHomomorphicScheme[
			*elgamal.PrivateKey[E, S], *elgamal.PublicKey[E, S],
			*elgamal.Plaintext[E, S], E,
			*elgamal.Ciphertext[E, S], *constructions.FiniteDirectSumModuleElement[E, S],
			*elgamal.Nonce[S], S,
			*elgamal.KeyGenerator[E, S], *elgamal.Encrypter[E, S], *elgamal.Decrypter[E, S], algebra.Numeric,
		] = (*elgamal.Scheme[E, S])(nil)
	)

	var (
		_ cbor.Marshaler   = (*elgamal.Plaintext[E, S])(nil)
		_ cbor.Unmarshaler = (*elgamal.Plaintext[E, S])(nil)
		_ cbor.Marshaler   = (*elgamal.Nonce[S])(nil)
		_ cbor.Unmarshaler = (*elgamal.Nonce[S])(nil)
		_ cbor.Marshaler   = (*elgamal.Ciphertext[E, S])(nil)
		_ cbor.Unmarshaler = (*elgamal.Ciphertext[E, S])(nil)
		_ cbor.Marshaler   = (*elgamal.PublicKey[E, S])(nil)
		_ cbor.Unmarshaler = (*elgamal.PublicKey[E, S])(nil)
		_ cbor.Marshaler   = (*elgamal.PrivateKey[E, S])(nil)
		_ cbor.Unmarshaler = (*elgamal.PrivateKey[E, S])(nil)
	)

}
