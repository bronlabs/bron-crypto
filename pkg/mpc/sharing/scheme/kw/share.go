package kw

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// Share is a single shareholder's portion of a KW secret. It consists of the
// shareholder's ID and a vector of field elements — one per MSP row owned by
// that shareholder. For ideal MSPs the vector has length one.
type Share[FE algebra.PrimeFieldElement[FE]] struct {
	id sharing.ID
	v  []FE
}

type shareDTO[FE algebra.PrimeFieldElement[FE]] struct {
	ID sharing.ID `cbor:"id"`
	V  []FE       `cbor:"value"`
}

// NewShare creates a share for the given holder ID with the provided values.
func NewShare[FE algebra.PrimeFieldElement[FE]](id sharing.ID, v ...FE) (*Share[FE], error) {
	if id == 0 || len(v) == 0 || sliceutils.Any(v, func(vi FE) bool { return utils.IsNil(vi) }) {
		return nil, sharing.ErrIsNil.WithMessage("id or value is nil")
	}
	return &Share[FE]{
		id: id,
		v:  v,
	}, nil
}

// ID returns the shareholder identifier.
func (s *Share[FE]) ID() sharing.ID {
	return s.id
}

// Value returns the share's field element vector.
func (s *Share[FE]) Value() []FE {
	return s.v
}

// Equal reports whether two shares have the same ID and value vector.
func (s *Share[FE]) Equal(other *Share[FE]) bool {
	if s == nil || other == nil {
		return s == other
	}
	if s.id != other.id {
		return false
	}
	if len(s.v) != len(other.v) {
		return false
	}
	for i := range s.v {
		if !s.v[i].Equal(other.v[i]) {
			return false
		}
	}
	return true
}

// Op is an alias for Add, satisfying the generic group-element interface.
func (s *Share[FE]) Op(other *Share[FE]) *Share[FE] {
	return s.Add(other)
}

// Add returns a new share whose value vector is the component-wise sum of
// s and other. Both shares must belong to the same holder. This enables the
// linear homomorphic property: Add(share(a), share(b)) reconstructs to a + b.
func (s *Share[FE]) Add(other *Share[FE]) *Share[FE] {
	if s.id != other.id {
		panic("cannot operate on shares with different IDs")
	}
	out := make([]FE, len(s.v))
	for i := range s.v {
		out[i] = s.v[i].Add(other.v[i])
	}
	return &Share[FE]{
		id: s.id,
		v:  out,
	}
}

// ScalarOp is an alias for ScalarMul, satisfying the generic module-element interface.
func (s *Share[FE]) ScalarOp(scalar algebra.Numeric) *Share[FE] {
	return s.ScalarMul(scalar)
}

// ScalarMul returns a new share with each component multiplied by the scalar.
// This enables the linear homomorphic property: ScalarMul(share(a), k) reconstructs to k * a.
func (s *Share[FE]) ScalarMul(scalar algebra.Numeric) *Share[FE] {
	out := make([]FE, len(s.v))
	for i := range s.v {
		out[i] = algebrautils.ScalarMul(s.v[i], scalar)
	}
	return &Share[FE]{
		id: s.id,
		v:  out,
	}
}

// HashCode returns a deterministic hash combining the ID and all value components.
func (s *Share[FE]) HashCode() base.HashCode {
	out := base.HashCode(s.id)
	for _, fe := range s.v {
		out = out.Combine(fe.HashCode())
	}
	return out
}

// MarshalCBOR serialises the share to CBOR.
func (s *Share[FE]) MarshalCBOR() ([]byte, error) {
	dto := shareDTO[FE]{
		ID: s.id,
		V:  s.v,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal KW Share")
	}
	return data, nil
}

// UnmarshalCBOR deserialises a share from CBOR, validating the result.
func (s *Share[FE]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*shareDTO[FE]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal KW Share")
	}
	ss, err := NewShare(dto.ID, dto.V...)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid share data")
	}
	s.id = ss.id
	s.v = ss.v
	return nil
}
