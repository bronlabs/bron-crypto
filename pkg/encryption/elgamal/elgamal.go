package elgamal

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

const Name encryption.Name = "elgamal"

type UnderlyingGroup[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] interface {
	algebra.AbelianGroup[E, S]
	algebra.CyclicGroup[E]
	algebra.FiniteGroup[E]
}

type UnderlyingGroupElement[E interface {
	algebra.AbelianGroupElement[E, S]
	algebra.CyclicGroupElement[E]
}, S algebra.UintLike[S]] interface {
	algebra.AbelianGroupElement[E, S]
	algebra.CyclicGroupElement[E]
}

func NewScheme[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]](g UnderlyingGroup[E, S], zn algebra.ZModLike[S]) (*Scheme[E, S], error) {
	if g == nil {
		return nil, ErrIsNil.WithMessage("g")
	}
	if zn == nil {
		return nil, ErrIsNil.WithMessage("zn")
	}
	ctSpace, err := NewCiphertextSpace(g)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create ciphertext space")
	}
	return &Scheme[E, S]{g, zn, ctSpace}, nil
}

type Scheme[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
	g       UnderlyingGroup[E, S]
	zn      algebra.ZModLike[S]
	ctSpace *CiphertextSpace[E, S]
}

func (*Scheme[E, S]) Name() encryption.Name {
	return Name
}

func (s *Scheme[E, S]) Group() UnderlyingGroup[E, S] {
	if s == nil {
		return nil
	}
	return s.g
}

func (s *Scheme[E, S]) ScalarRing() algebra.ZModLike[S] {
	if s == nil {
		return nil
	}
	return s.zn
}

func (s *Scheme[E, S]) CiphertextSpace() *CiphertextSpace[E, S] {
	if s == nil {
		return nil
	}
	return s.ctSpace
}

func (s *Scheme[E, S]) Keygen(opts ...KeyGeneratorOption[E, S]) (*KeyGenerator[E, S], error) {
	kg := &KeyGenerator[E, S]{s.g, s.zn}
	for _, opt := range opts {
		if err := opt(kg); err != nil {
			return nil, errs.Wrap(err).WithMessage("key generator option failed")
		}
	}
	return kg, nil
}

func (s *Scheme[E, S]) Encrypter(opts ...EncrypterOption[E, S]) (*Encrypter[E, S], error) {
	enc := &Encrypter[E, S]{s.g, s.zn, s.ctSpace}
	for _, opt := range opts {
		if err := opt(enc); err != nil {
			return nil, errs.Wrap(err).WithMessage("encrypter option failed")
		}
	}
	return enc, nil
}

func (s *Scheme[E, S]) Decrypter(sk *PrivateKey[E, S], opts ...DecrypterOption[E, S]) (*Decrypter[E, S], error) {
	out := &Decrypter[E, S]{sk}
	for _, opt := range opts {
		if err := opt(out); err != nil {
			return nil, errs.Wrap(err).WithMessage("decrypter option failed")
		}
	}
	return out, nil
}
