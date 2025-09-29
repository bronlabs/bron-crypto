package pedersen

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	pedcom "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	"github.com/fxamacker/cbor/v2"
)

type Share[S algebra.PrimeFieldElement[S]] struct {
	id       sharing.ID
	secret   *pedcom.Message[S]
	blinding *pedcom.Witness[S]
}

type shareDTO[S algebra.PrimeFieldElement[S]] struct {
	ID       sharing.ID         `cbor:"sharingId"`
	Secret_  *pedcom.Message[S] `cbor:"secret"`
	Blinding *pedcom.Witness[S] `cbor:"blinding"`
}

func NewShare[S algebra.PrimeFieldElement[S]](id sharing.ID, secret *pedcom.Message[S], blinding *pedcom.Witness[S], ac *AccessStructure) (*Share[S], error) {
	if secret == nil {
		return nil, errs.NewIsNil("secret cannot be nil")
	}
	if blinding == nil {
		return nil, errs.NewIsNil("blinding cannot be nil")
	}
	if ac != nil && !ac.Shareholders().Contains(id) {
		return nil, errs.NewMembership("share ID %d is not a valid shareholder", id)
	}
	return &Share[S]{
		id:       id,
		secret:   secret,
		blinding: blinding,
	}, nil
}

func (s *Share[S]) ID() sharing.ID {
	return s.id
}

func (s *Share[S]) Value() S {
	return s.secret.Value()
}

func (s *Share[S]) Blinding() *pedcom.Witness[S] {
	if s == nil {
		return nil
	}
	return s.blinding
}

func (s *Share[S]) Secret() *pedcom.Message[S] {
	if s == nil {
		return nil
	}
	return s.secret
}

func (s *Share[S]) Op(other *Share[S]) *Share[S] {
	return &Share[S]{
		id:       s.id,
		secret:   s.secret.Op(other.secret),
		blinding: s.blinding.Op(other.blinding),
	}
}

func (s *Share[S]) Add(other *Share[S]) *Share[S] {
	return s.Op(other)
}

func (s *Share[S]) ScalarOp(scalar S) *Share[S] {
	// Special case: multiplying by zero is not supported in Pedersen VSS
	// because it would require a zero blinding factor, which is not allowed
	if scalar.IsZero() {
		panic(errs.NewIsZero("cannot multiply Pedersen share by zero - zero blinding factors are not allowed"))
	}

	w2, err := pedcom.NewWitness(scalar)
	if err != nil {
		panic(errs.WrapFailed(err, "could not create witness from scalar"))
	}
	m2 := pedcom.NewMessage(scalar)
	return &Share[S]{
		id:       s.id,
		secret:   s.secret.Mul(m2),
		blinding: s.blinding.Mul(w2),
	}
}

func (s *Share[S]) ScalarMul(scalar S) *Share[S] {
	return s.ScalarOp(scalar)
}

func (s *Share[S]) HashCode() base.HashCode {
	return s.secret.HashCode() ^ s.blinding.HashCode()
}

func (s *Share[S]) Equal(other *Share[S]) bool {
	if s == nil || other == nil {
		return s == other
	}
	return s.secret.Equal(other.secret) && s.blinding.Equal(other.blinding)
}

func (s *Share[S]) Bytes() []byte {
	return slices.Concat(
		s.secret.Value().Bytes(),
		s.blinding.Value().Bytes(),
	)
}

func (s *Share[S]) ToAdditive(qualifiedSet sharing.MinimalQualifiedAccessStructure) (*additive.Share[S], error) {
	ss, err := shamir.NewShare(s.id, s.secret.Value(), nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create shamir share from share")
	}
	return ss.ToAdditive(qualifiedSet)
}

func (s *Share[S]) MarshalCBOR() ([]byte, error) {
	dto := shareDTO[S]{
		ID:       s.id,
		Secret_:  s.secret,
		Blinding: s.blinding,
	}
	return cbor.Marshal(dto)
}

func (s *Share[S]) UnmarshalCBOR(data []byte) error {
	var dto shareDTO[S]
	if err := cbor.Unmarshal(data, &dto); err != nil {
		return err
	}

	s2, err := NewShare(dto.ID, dto.Secret_, dto.Blinding, nil)
	if err != nil {
		return err
	}
	*s = *s2
	return nil
}
