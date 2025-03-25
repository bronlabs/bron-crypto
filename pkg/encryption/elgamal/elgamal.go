package elgamal

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/groups"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

const (
	Type   encryption.Type = "elgamal"
	TypeEC encryption.Type = "elgamal in the exponent"
)

type UnderlyingGroup[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] interface {
	groups.FiniteAbelianGroup[E, S]
	algebra.CyclicSemiGroup[E]
}

type UnderlyingGroupElement[E interface {
	groups.FiniteAbelianGroupElement[E, S]
	algebra.CyclicSemiGroupElement[E]
}, S algebra.UintLike[S]] interface {
	groups.FiniteAbelianGroupElement[E, S]
	algebra.CyclicSemiGroupElement[E]
}

type SchemeElement[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct{}

func (*SchemeElement[E, S]) Scheme() types.Scheme[encryption.Type] {
	return nil
}

func (*SchemeElement[E, S]) Type() encryption.Type {
	//TODO: some helper for EC detection
	return Type
}

// type PublicKeySpace[PK PublicKey[PK, S], S algebra.UintLike[S]] UnderlyingGroup[PK, S]

// type PublicKey[PK UnderlyingGroupElement[PK, S], S algebra.UintLike[S]] struct {
// 	UnderlyingGroupElement[PK, S]
// }

// type MessageSpace[M Message[M, S], S algebra.UintLike[S]] UnderlyingGroup[M, S]
// type Message[M UnderlyingGroupElement[M, S], S algebra.UintLike[S]] UnderlyingGroupElement[M, S]

// type Encode[M Message[M, S], S algebra.UintLike[S]] func(b []byte) (M, error)
// type Decode[M Message[M, S], S algebra.UintLike[S]] func(m M) ([]byte, error)

// type PrivateKeySpace[K PrivateKeyyy[K]] algebra.ZnLike[K]

// type PrivateKeyyy[K algebra.UintLike[K]] algebra.UintLike[K]

type Plaintext[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
	SchemeElement[E, S]
	decoder encryption.Decoder[*Plaintext[E, S]]
	v       E
}

func (p *Plaintext[E, S]) Decode() ([]byte, error) {
	out, err := p.decoder(p)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to decode plaintext")
	}
	return out, nil
}

type PublicKey[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
	SchemeElement[E, S]
	v E
}

func (pk *PublicKey[E, S]) Equal(x *PublicKey[E, S]) bool {
	return pk.v.Equal(x.v)
}

func (pk *PublicKey[E, S]) Clone() *PublicKey[E, S] {
	out := &PublicKey[E, S]{}
	out.v = pk.v.Clone()
	return out
}

type PrivateKey[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
	v  E
	pk PublicKey[E, S]
}

type Ciphertext[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
}

type Nonce[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
}

// type scheme[G UnderlyingGroup[E, S], E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct{}

// func (s *scheme[G, E, S]) Type() encryption.Type {
// 	//TODO: some helper for EC detection
// 	return Type
// }
