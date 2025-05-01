package encryption

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/groups"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
)

type Type types.Type

type PublicKey[PK any] types.PublicKey[PK]
type PrivateKey[SK any, PK PublicKey[PK]] types.PrivateKey[SK, PK]

type Plaintext any
type PlaintextCodec[P Plaintext] struct {
	Encoder func([]byte) (P, error)
	Decoder func(P) ([]byte, error)
}

type Ciphertext any
type Nonce any

type Rerandomisable[T any] interface {
	Rerandomise(types.PRNG) (T, error)
}

func GetEncryptionScheme[SK PrivateKey[SK, PK], PK PublicKey[PK], P Plaintext, C Ciphertext, N Nonce](participant types.Participant[Type]) Scheme[SK, PK, P, C, N] {
	out, ok := participant.Scheme().(Scheme[SK, PK, P, C, N])
	if !ok {
		panic("invalid encryption scheme object")
	}
	return out
}

type KeyGenerator[SK PrivateKey[SK, PK], PK PublicKey[PK]] interface {
	types.Participant[Type]
	Generate(prng types.PRNG, opts any) (SK, error)
}

type Encrypter[PK PublicKey[PK], P Plaintext, C Ciphertext, N Nonce] interface {
	types.Participant[Type]
	Encrypt(plaintext P, receiver PK, prng types.PRNG, opts any) (ciphertext C, nonce N, err error)
	EncryptWithNonce(plaintext P, receiver PK, nonce N, opts any) (ciphertext C, err error)
}

type Decrypter[SK PrivateKey[SK, PK], PK PublicKey[PK], P Plaintext, C Ciphertext] interface {
	types.Participant[Type]
	PrivateKey() SK
	Decrypt(ciphertext C, opts any) (plaintext P, err error)
}

type LinearlyRandomisedDecrypter[SK PrivateKey[SK, PK], PK PublicKey[PK], P Plaintext, C interface {
	Ciphertext
	Rerandomisable[C]
}, N Nonce] interface {
	Decrypter[SK, PK, P, C]
	DecryptWithNonce(ciphertext C, nonce N, opts any) (plaintext P, err error)
}
type Scheme[SK PrivateKey[SK, PK], PK PublicKey[PK], P Plaintext, C Ciphertext, N Nonce] interface {
	types.Scheme[Type]
	Keygen() KeyGenerator[SK, PK]
	Encrypter() Encrypter[PK, P, C, N]
	Decrypter(SK) Decrypter[SK, PK, P, C]
}

// ******** Homomorphic

type Homomorphic[T any, TV groups.GroupElement[TV]] interface {
	types.Transparent[TV]
	Wrap(TV) error
}
type AdditivelyHomomorphic[T any, TV groups.AdditiveGroupElement[TV]] Homomorphic[T, TV]
type MultiplicativelyHomomorphic[T any, TV groups.MultiplicativeGroupElement[TV]] Homomorphic[T, TV]

type HomomorphicScheme[
	SK PrivateKey[SK, PK], PK PublicKey[PK],
	P interface {
		Plaintext
		Homomorphic[P, PV]
	}, PV groups.GroupElement[PV],
	C interface {
		Ciphertext
		Homomorphic[C, CV]
		algebra.Actable[C, P]
	}, CV groups.GroupElement[CV],
	N interface {
		Nonce
		Homomorphic[N, NV]
	}, NV groups.GroupElement[NV],
] Scheme[SK, PK, P, C, N]
