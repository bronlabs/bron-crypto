package elgamal

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

// Name is the canonical identifier for this encryption scheme.
const Name encryption.Name = "elgamal"

// UnderlyingGroup constrains the group G in which ElGamal operates.
// G must be a finite abelian cyclic group whose DDH problem is hard.
// Typical instantiations: prime-order elliptic curve groups (k256, p256, ed25519 prime subgroup).
type UnderlyingGroup[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] interface {
	algebra.AbelianGroup[E, S]
	algebra.CyclicGroup[E]
	algebra.FiniteGroup[E]
}

// UnderlyingGroupElement constrains elements of the group G.
type UnderlyingGroupElement[E interface {
	algebra.AbelianGroupElement[E, S]
	algebra.CyclicGroupElement[E]
}, S algebra.UintLike[S]] interface {
	algebra.AbelianGroupElement[E, S]
	algebra.CyclicGroupElement[E]
}

// NewScheme creates an ElGamal scheme over group g with scalar ring zn.
// The scalar ring must be Z/nZ where n is the order of the group.
func NewScheme[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]](g UnderlyingGroup[E, S], zn algebra.ZModLike[S]) (*Scheme[E, S], error) {
	if g == nil {
		return nil, ErrIsNil.WithMessage("g")
	}
	if zn == nil {
		return nil, ErrIsNil.WithMessage("zn")
	}
	return &Scheme[E, S]{g, zn}, nil
}

// Scheme holds the algebraic parameters for an ElGamal instantiation and
// serves as a factory for KeyGenerator, Encrypter, and Decrypter.
type Scheme[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
	g  UnderlyingGroup[E, S]
	zn algebra.ZModLike[S]
}

// Name returns the scheme identifier "elgamal".
func (*Scheme[E, S]) Name() encryption.Name {
	return Name
}

// Group returns the underlying cyclic group G.
func (s *Scheme[E, S]) Group() UnderlyingGroup[E, S] {
	if s == nil {
		return nil
	}
	return s.g
}

// ScalarRing returns Z/nZ, where n = |G|.
func (s *Scheme[E, S]) ScalarRing() algebra.ZModLike[S] {
	if s == nil {
		return nil
	}
	return s.zn
}

// Keygen returns a KeyGenerator that produces (sk, pk) pairs.
func (s *Scheme[E, S]) Keygen(opts ...KeyGeneratorOption[E, S]) (*KeyGenerator[E, S], error) {
	kg := &KeyGenerator[E, S]{s.g, s.zn}
	for _, opt := range opts {
		if err := opt(kg); err != nil {
			return nil, errs.Wrap(err).WithMessage("key generator option failed")
		}
	}
	return kg, nil
}

// Encrypter returns an Encrypter bound to this scheme's group and scalar ring.
func (s *Scheme[E, S]) Encrypter(opts ...EncrypterOption[E, S]) (*Encrypter[E, S], error) {
	enc := &Encrypter[E, S]{s.g, s.zn}
	for _, opt := range opts {
		if err := opt(enc); err != nil {
			return nil, errs.Wrap(err).WithMessage("encrypter option failed")
		}
	}
	return enc, nil
}

// Decrypter returns a Decrypter bound to the given private key.
func (*Scheme[E, S]) Decrypter(sk *PrivateKey[E, S], opts ...DecrypterOption[E, S]) (*Decrypter[E, S], error) {
	out := &Decrypter[E, S]{sk}
	for _, opt := range opts {
		if err := opt(out); err != nil {
			return nil, errs.Wrap(err).WithMessage("decrypter option failed")
		}
	}
	return out, nil
}
