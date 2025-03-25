package encryption

import (
	"crypto"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
)

type Type types.Type

type PrivateKey[K types.PrivateKey[K, PK, Type], PK PublicKey[PK]] interface {
	types.PrivateKey[K, PK, Type]
	types.SchemeElement[Type]
}

type PublicKey[PK algebra.Element[PK]] interface {
	types.PublicKey[PK, Type]
	types.SchemeElement[Type]
}

type Encoder[P Plaintext] func([]byte) (P, error)
type Decoder[P Plaintext] func(P) ([]byte, error)

type Plaintext interface {
	types.SchemeElement[Type]
	Decode() ([]byte, error)
}

type Ciphertext types.SchemeElement[Type]

type Nonce types.SchemeElement[Type]

func GetEncryptionScheme[T types.SchemeElement[Type], K types.PrivateKey[K, PK, Type], PK types.PublicKey[PK, Type], P Plaintext, C Ciphertext, N Nonce](x T) Scheme[K, PK, P, C, N] {
	out, ok := x.Scheme().(Scheme[K, PK, P, C, N])
	if !ok {
		panic("invalid encryption scheme object")
	}
	return out
}

type KeygenOpts types.SchemeElement[Type]
type Keygen[K PrivateKey[K, PK], PK PublicKey[PK]] func(prng types.PRNG, opts KeygenOpts) (K, PK, error)
type KeyGenerator[K PrivateKey[K, PK], PK PublicKey[PK], P Plaintext, C Ciphertext, N Nonce] interface {
	types.Participant[Scheme[K, PK, P, C, N], Type]
	Keygen(prng types.PRNG, opts KeygenOpts) (K, PK, error)
}

type EncryptionOpts types.SchemeElement[Type]
type RandomisedEncryptionOpts interface {
	EncryptionOpts
	Prng() types.PRNG
}
type NonceEncryptionOpts[N Nonce] interface {
	EncryptionOpts
	Nonce() N
}
type Encrypt[P Plaintext, C Ciphertext, N Nonce, PK PublicKey[PK]] func(plaintext P, receiver PK, opts EncryptionOpts) (C, N, error)

type Encrypter[K PrivateKey[K, PK], PK PublicKey[PK], P Plaintext, C Ciphertext, N Nonce] interface {
	types.Participant[Scheme[K, PK, P, C, N], Type]
	Encrypt(plaintext P, receiver PK, opts EncryptionOpts) (ciphertext C, nonce N, err error)
}

type DecryptionOpts interface {
	types.SchemeElement[Type]
	crypto.DecrypterOpts
}
type Decrypter[K PrivateKey[K, PK], PK PublicKey[PK], P Plaintext, C Ciphertext, N Nonce] interface {
	types.Participant[Scheme[K, PK, P, C, N], Type]
	PublicKey() PK
	Decrypt(ciphertext C, sender PK, opts DecryptionOpts) (plaintext P, err error)
	AsGoDecrypter() crypto.Decrypter
}

type Scheme[K PrivateKey[K, PK], PK PublicKey[PK], P Plaintext, C Ciphertext, N Nonce] interface {
	types.Scheme[Type]
	Keygen() KeyGenerator[K, PK, P, C, N]
	Encrypter() Encrypter[K, PK, P, C, N]
	Decrypter() Decrypter[K, PK, P, C, N]
}

type HomomorphicPlaintext[P interface {
	Plaintext
	algebra.AbelianGroupElement[P, S]
}, S algebra.IntLike[S]] interface {
	Plaintext
	algebra.AbelianGroupElement[P, S]
}

type HomomorphicCiphertext[C interface {
	Ciphertext
	algebra.AbelianGroupElement[C, S]
}, S algebra.IntLike[S]] interface {
	Ciphertext
	algebra.AbelianGroupElement[C, S]
}

type HomomorphicNonce[N interface {
	Nonce
	algebra.AbelianGroupElement[N, S]
}, S algebra.IntLike[S]] interface {
	Nonce
	algebra.AbelianGroupElement[N, S]
}

type HomomorphicScheme[K PrivateKey[K, PK], PK PublicKey[PK], P HomomorphicPlaintext[P, S], C HomomorphicCiphertext[C, S], N HomomorphicNonce[N, S], S algebra.IntLike[S]] Scheme[K, PK, P, C, N]

func _[K PrivateKey[K, PK], PK PublicKey[PK], P Plaintext, C Ciphertext, N Nonce]() {
	var g KeyGenerator[K, PK, P, C, N]
	var _ Keygen[K, PK] = g.Keygen

	var v Encrypter[K, PK, P, C, N]
	var _ Encrypt[P, C, N, PK] = v.Encrypt
}
