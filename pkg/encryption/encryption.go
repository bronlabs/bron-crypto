package encryption

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/groups"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
)

type Type types.Type

type PublicKey[PK types.SchemeElement[Type]] types.OpaquePublicKey[PK, Type]
type PrivateKey[SK types.SchemeElement[Type], PK PublicKey[PK]] types.OpaquePrivateKey[SK, PK, Type]

type Plaintext any
type PlaintextCodec[P Plaintext] struct {
	Encoder func([]byte) (P, error)
	Decoder func(P) ([]byte, error)
}

type Ciphertext any
type Nonce any

func GetEncryptionScheme[SK PrivateKey[SK, PK], PK PublicKey[PK], P Plaintext, C Ciphertext, N Nonce](x types.SchemeElement[Type]) Scheme[SK, PK, P, C, N] {
	out, ok := x.Scheme().(Scheme[SK, PK, P, C, N])
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

type Scheme[SK PrivateKey[SK, PK], PK PublicKey[PK], P Plaintext, C Ciphertext, N Nonce] interface {
	types.Scheme[Type]
	Keygen() KeyGenerator[SK, PK]
	Encrypter() Encrypter[PK, P, C, N]
	Decrypter(SK) Decrypter[SK, PK, P, C]
}

// ******** Homomorphic

type Homomorphic[TV groups.GroupElement[TV]] types.Transparent[TV]
type AdditivelyHomomorphic[TV groups.GroupElement[TV]] Homomorphic[TV]
type MultiplicativelyHomomorphic[TV groups.GroupElement[TV]] Homomorphic[TV]

type HomomorphicScheme[
	SK PrivateKey[SK, PK], PK PublicKey[PK],
	P interface {
		Plaintext
		Homomorphic[PV]
	}, PV groups.GroupElement[PV],
	C interface {
		Ciphertext
		Homomorphic[CV]
	}, CV groups.GroupElement[CV],
	N interface {
		Nonce
		Homomorphic[NV]
	}, NV groups.GroupElement[NV]] Scheme[SK, PK, P, C, N]
