package shamir

import (
	"encoding/binary"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/scheme/additive"
	"github.com/bronlabs/errs-go/errs"
)

// Share represents a Shamir secret share, consisting of an evaluation point (ID)
// and the polynomial value at that point.
type Share[FE algebra.PrimeFieldElement[FE]] struct {
	id sharing.ID
	v  FE
}

type shareDTO[FE algebra.PrimeFieldElement[FE]] struct {
	ID sharing.ID `cbor:"sharingID"`
	V  FE         `cbor:"value"`
}

// NewShare creates a new Shamir share with the given ID and value.
// If an access structure is provided, validates that the ID is a valid shareholder.
func NewShare[FE algebra.PrimeFieldElement[FE]](id sharing.ID, value FE, ac *sharing.ThresholdAccessStructure) (*Share[FE], error) {
	if ac != nil && !ac.Shareholders().Contains(id) {
		return nil, sharing.ErrMembership.WithMessage("share ID %d is not a valid shareholder", id)
	}
	return &Share[FE]{
		id: id,
		v:  value,
	}, nil
}

// ToAdditive converts this Shamir share to an additive share by multiplying
// by the appropriate Lagrange coefficient. The resulting additive shares can
// be summed to reconstruct the secret.
func (s *Share[FE]) ToAdditive(qualifiedSet *sharing.UnanimityAccessStructure) (*additive.Share[FE], error) {
	field, ok := s.v.Structure().(algebra.PrimeField[FE])
	if !ok {
		return nil, sharing.ErrType.WithMessage("share value does not implement Field interface")
	}
	lambdas, err := LagrangeCoefficients(field, qualifiedSet.Shareholders().List()...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute Lagrange coefficients")
	}
	lambdaI, exists := lambdas.Get(s.id)
	if !exists {
		return nil, sharing.ErrMembership.WithMessage("share ID %d is not a valid shareholder", s.id)
	}
	converted := lambdaI.Mul(s.v)
	additiveShare, err := additive.NewShare(s.id, converted, qualifiedSet)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to convert Shamir share to additive")
	}
	return additiveShare, nil
}

// ID returns the shareholder identifier for this share.
func (s *Share[_]) ID() sharing.ID {
	return s.id
}

// Value returns the share value (the polynomial evaluation at ID).
func (s *Share[FE]) Value() FE {
	return s.v
}

// Equal returns true if two shares have the same ID and value.
func (s *Share[FE]) Equal(other *Share[FE]) bool {
	if s == nil || other == nil {
		return s == other
	}
	return s.id == other.id && s.v.Equal(other.v)
}

// Op is an alias for Add, implementing the group element interface.
func (s *Share[FE]) Op(other *Share[FE]) *Share[FE] {
	return s.Add(other)
}

// Add returns a new share that is the component-wise sum of two shares.
// Both shares must have the same ID.
func (s *Share[FE]) Add(other *Share[FE]) *Share[FE] {
	if s.id != other.id {
		panic("cannot add shares with different IDs")
	}
	return &Share[FE]{
		id: s.id,
		v:  s.v.Add(other.v),
	}
}

// SubPlain subtracts a plaintext value from this share.
func (s *Share[FE]) SubPlain(other FE) *Share[FE] {
	return &Share[FE]{
		id: s.id,
		v:  s.v.Sub(other),
	}
}

// ScalarOp is an alias for ScalarMul.
func (s *Share[FE]) ScalarOp(scalar FE) *Share[FE] {
	return s.ScalarMul(scalar)
}

// ScalarMul returns a new share with the value multiplied by a scalar.
func (s *Share[FE]) ScalarMul(scalar FE) *Share[FE] {
	return &Share[FE]{
		id: s.id,
		v:  s.v.Mul(scalar),
	}
}

// Clone returns a deep copy of this share.
func (s *Share[FE]) Clone() *Share[FE] {
	return &Share[FE]{
		id: s.id,
		v:  s.v.Clone(),
	}
}

// HashCode returns a hash code for this share, for use in hash-based collections.
func (s *Share[FE]) HashCode() base.HashCode {
	return base.HashCode(s.id) ^ s.v.HashCode()
}

// Bytes returns the canonical byte representation of this share.
func (s *Share[FE]) Bytes() []byte {
	buf := s.Value().Bytes()
	binary.BigEndian.AppendUint64(buf, uint64(s.ID()))
	return buf
}

// MarshalCBOR serializes the share.
func (s *Share[FE]) MarshalCBOR() ([]byte, error) {
	dto := &shareDTO[FE]{
		ID: s.id,
		V:  s.v,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal Shamir Share")
	}
	return data, nil
}

// UnmarshalCBOR deserializes the share.
func (s *Share[FE]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*shareDTO[FE]](data)
	if err != nil {
		return err
	}

	s2, err := NewShare(dto.ID, dto.V, nil)
	if err != nil {
		return err
	}
	*s = *s2
	return nil
}
