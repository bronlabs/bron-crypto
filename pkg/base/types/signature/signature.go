package signature

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
type PublicKey[PK types.PublicKey[PK, Type]] interface {
	types.PublicKey[PK, Type]
	types.SchemeElement[Type]
}
type Message interface {
	~[]byte
	types.SchemeElement[Type]
}

type Signature interface {
	algebra.Element[Signature]
	types.SchemeElement[Type]
}

func GetSignatureScheme[T types.SchemeElement[Type], K types.PrivateKey[K, PK, Type], PK types.PublicKey[PK, Type], S Signature, M Message](x T) Scheme[K, PK, S, M] {
	out, ok := x.Scheme().(Scheme[K, PK, S, M])
	if !ok {
		panic("invalid signature scheme object")
	}
	return out
}

type KeygenOpts any
type SigningOpts crypto.SignerOpts
type RandomisedSigningOpts interface {
	SigningOpts
	Prng() types.PRNG
}

type Keygen[K PrivateKey[K, PK], PK PublicKey[PK]] func(prng types.PRNG, opts KeygenOpts) (K, PK, error)

type KeyGenerator[K PrivateKey[K, PK], PK PublicKey[PK], S Signature, M Message] interface {
	types.Participant[Scheme[K, PK, S, M], Type]
	Keygen(prng types.PRNG, opts KeygenOpts) (K, PK, error)
}

type Signer[K PrivateKey[K, PK], PK PublicKey[PK], S Signature, M Message] interface {
	types.Participant[Scheme[K, PK, S, M], Type]
	Sign(message M, opts SigningOpts) (S, error)
	AsGoSigner() crypto.Signer
}

type Verify[K PrivateKey[K, PK], PK PublicKey[PK], S Signature, M Message] func(signature S, message M, signer PK, opts SigningOpts) error

type Verifier[K PrivateKey[K, PK], PK PublicKey[PK], S Signature, M Message] interface {
	types.Participant[Scheme[K, PK, S, M], Type]
	Verify(signature S, message M, signer PK, opts SigningOpts) error
	PublicKey() PK
}

type Scheme[K PrivateKey[K, PK], PK PublicKey[PK], S Signature, M Message] interface {
	types.Scheme[Type]
	Keygen() KeyGenerator[K, PK, S, M]
	Signer() Signer[K, PK, S, M]
	Verifier() Verifier[K, PK, S, M]
}

func _[K PrivateKey[K, PK], PK PublicKey[PK], S Signature, M Message]() {
	var g KeyGenerator[K, PK, S, M]
	var _ Keygen[K, PK] = g.Keygen

	var v Verifier[K, PK, S, M]
	var _ Verify[K, PK, S, M] = v.Verify
}
