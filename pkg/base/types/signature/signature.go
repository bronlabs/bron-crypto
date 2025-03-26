package signature

import (
	"hash"

	"github.com/bronlabs/bron-crypto/pkg/base/types"
)

type Type types.Type

type PublicKey[PK types.SchemeElement[Type]] types.OpaquePublicKey[PK, Type]
type PrivateKey[SK types.SchemeElement[Type], PK PublicKey[PK]] types.OpaquePrivateKey[SK, PK, Type]
type Message interface {
	~[]byte
	types.SchemeElement[Type]
}
type Signature types.SchemeElement[Type]

func GetSignatureScheme[SK PrivateKey[SK, PK], PK PublicKey[PK], M Message, S Signature](x types.SchemeElement[Type]) Scheme[SK, PK, M, S] {
	out, ok := x.Scheme().(Scheme[SK, PK, M, S])
	if !ok {
		panic("invalid signature scheme object")
	}
	return out
}

type KeyGenerator[SK PrivateKey[SK, PK], PK PublicKey[PK], M Message, S Signature] interface {
	types.Participant[Type]
	Keygen(prng types.PRNG, opts any) (SK, error)
}

type Signer[SK PrivateKey[SK, PK], PK PublicKey[PK], M Message, S Signature] interface {
	types.Participant[Type]
	PrivateKey() SK
	Sign(message M, opts any) (S, error)
}

type Verify[SK PrivateKey[SK, PK], PK PublicKey[PK], M Message, S Signature] func(signature S, message M, signer PK, h func() hash.Hash) error

type Verifier[SK PrivateKey[SK, PK], PK PublicKey[PK], M Message, S Signature] interface {
	types.Participant[Type]
	Verify(signature S, message M, signer PK, opts any) error
}

type Scheme[SK PrivateKey[SK, PK], PK PublicKey[PK], M Message, S Signature] interface {
	types.Scheme[Type]
	HashFunc() func() hash.Hash
	Keygen() KeyGenerator[SK, PK, M, S]
	Signer() Signer[SK, PK, M, S]
	Verifier() Verifier[SK, PK, M, S]
}
