package shamir

import (
	"encoding/binary"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
	"github.com/fxamacker/cbor/v2"
)

type Share[FE algebra.PrimeFieldElement[FE]] struct {
	id sharing.ID
	v  FE
}

type shareDTO[FE algebra.PrimeFieldElement[FE]] struct {
	ID sharing.ID `cbor:"sharingId"`
	V  FE         `cbor:"value"`
}

func NewShare[FE algebra.PrimeFieldElement[FE]](id sharing.ID, value FE, ac *AccessStructure) (*Share[FE], error) {
	if ac != nil && !ac.Shareholders().Contains(id) {
		return nil, errs.NewMembership("share ID %d is not a valid shareholder", id)
	}
	return &Share[FE]{
		id: id,
		v:  value,
	}, nil
}

func (s *Share[FE]) ToAdditive(qualifiedSet sharing.MinimalQualifiedAccessStructure) (*additive.Share[FE], error) {
	field, ok := s.v.Structure().(algebra.PrimeField[FE])
	if !ok {
		return nil, errs.NewType("share value does not implement Field interface")
	}
	lambdas, err := LagrangeCoefficients(field, qualifiedSet.Shareholders().List()...)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute Lagrange coefficients")
	}
	lambda_i, exists := lambdas.Get(s.id)
	if !exists {
		return nil, errs.NewMembership("share ID %d is not a valid shareholder", s.id)
	}
	converted := lambda_i.Mul(s.v)
	return additive.NewShare(s.id, converted, &qualifiedSet)
}

func (s *Share[_]) ID() sharing.ID {
	return s.id
}

func (s *Share[FE]) Value() FE {
	return s.v
}

func (s *Share[FE]) Equal(other *Share[FE]) bool {
	if s == nil || other == nil {
		return s == other
	}
	return s.id == other.id && s.v.Equal(other.v)
}

func (s *Share[FE]) Op(other *Share[FE]) *Share[FE] {
	return s.Add(other)
}

func (s *Share[FE]) Add(other *Share[FE]) *Share[FE] {
	return &Share[FE]{
		id: s.id,
		v:  s.v.Add(other.v),
	}
}

func (s *Share[FE]) ScalarOp(scalar FE) *Share[FE] {
	return s.ScalarMul(scalar)
}

func (s *Share[FE]) ScalarMul(scalar FE) *Share[FE] {
	return &Share[FE]{
		id: s.id,
		v:  s.v.Mul(scalar),
	}
}

func (s *Share[FE]) Clone() *Share[FE] {
	return &Share[FE]{
		id: s.id,
		v:  s.v.Clone(),
	}
}

func (s *Share[FE]) HashCode() base.HashCode {
	return base.HashCode(s.id) ^ s.v.HashCode()
}

func (s *Share[FE]) Bytes() []byte {
	buf := s.Value().Bytes()
	binary.BigEndian.AppendUint64(buf, uint64(s.ID()))
	return buf
}

func (s *Share[FE]) MarshalCBOR() ([]byte, error) {
	dto := &shareDTO[FE]{
		ID: s.id,
		V:  s.v,
	}
	return cbor.Marshal(dto)
}

func (s *Share[FE]) UnmarshalCBOR(data []byte) error {
	var dto shareDTO[FE]
	if err := cbor.Unmarshal(data, &dto); err != nil {
		return err
	}

	s2, err := NewShare(dto.ID, dto.V, nil)
	if err != nil {
		return err
	}
	*s = *s2
	return nil
}
