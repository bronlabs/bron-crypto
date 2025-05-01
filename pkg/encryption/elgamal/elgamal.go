package elgamal

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/groups"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

const Type encryption.Type = "elgamal"

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

func NewScheme[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]](g UnderlyingGroup[E, S], z algebra.ZnLike[S]) (encryption.Scheme[*PrivateKey[E, S], *PublicKey[E, S], *Plaintext[E, S], *Ciphertext[E, S], *Nonce[E, S]], error) {
	if g == nil {
		return nil, errs.NewIsNil("group")
	}
	if z == nil {
		return nil, errs.NewIsNil("z")
	}
	return &scheme[E, S]{g, z}, nil
}

type scheme[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
	g UnderlyingGroup[E, S]
	z algebra.ZnLike[S]
}

func (s *scheme[E, S]) Type() encryption.Type {
	return Type
}

func (s *scheme[E, S]) Keygen() encryption.KeyGenerator[*PrivateKey[E, S], *PublicKey[E, S]] {
	return &keyGenerator[E, S]{s.g, s.z}
}

func (s *scheme[E, S]) Encrypter() encryption.Encrypter[*PublicKey[E, S], *Plaintext[E, S], *Ciphertext[E, S], *Nonce[E, S]] {
	return &encrypter[E, S]{s.g, s.z}
}

func (s *scheme[E, S]) Decrypter(sk *PrivateKey[E, S]) encryption.Decrypter[*PrivateKey[E, S], *PublicKey[E, S], *Plaintext[E, S], *Ciphertext[E, S]] {
	return &decrypter[E, S]{s.g, s.z, sk}
}
