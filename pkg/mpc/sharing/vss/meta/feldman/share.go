package feldman

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
)

// Share is a scalar share produced by the underlying KW linear secret sharing
// scheme. It is a type alias for kw.Share.
type Share[FE algebra.PrimeFieldElement[FE]] = kw.Share[FE]

// LiftShare maps a scalar share into a prime-order group by computing
// [v_i] * basePoint for each component. The resulting LiftedShare can be
// compared against the output of LiftedDealerFunc.ShareOf for Feldman-style
// verification.
func LiftShare[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]](s *Share[FE], basePoint E) (*LiftedShare[E, FE], error) {
	if s == nil {
		return nil, sharing.ErrIsNil.WithMessage("share cannot be nil")
	}
	if utils.IsNil(basePoint) {
		return nil, sharing.ErrIsNil.WithMessage("basePoint cannot be nil")
	}
	liftedValues := make([]E, len(s.Value()))
	for i, v := range s.Value() {
		liftedValues[i] = basePoint.ScalarOp(v)
	}
	out, err := NewLiftedShare(s.ID(), liftedValues...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create lifted share")
	}
	return out, nil
}

// NewLiftedShare creates a lifted share for the given holder ID with the
// provided group-element values — one per MSP row owned by that shareholder.
func NewLiftedShare[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]](id sharing.ID, v ...E) (*LiftedShare[E, FE], error) {
	if v == nil {
		return nil, sharing.ErrIsNil.WithMessage("value is nil")
	}
	if id == 0 {
		return nil, sharing.ErrIsZero.WithMessage("id cannot be zero")
	}
	return &LiftedShare[E, FE]{
		id: id,
		v:  v,
	}, nil
}

// LiftedShare is the group-element counterpart of Share. It holds a vector
// of group elements — one per MSP row — representing [lambda_i] * G for some
// base point G. Two lifted shares are equal iff they have the same ID and
// identical group-element vectors.
type LiftedShare[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	id sharing.ID
	v  []E
}

type liftedShareDTO[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	ID sharing.ID `cbor:"id"`
	V  []E        `cbor:"value"`
}

// ID returns the shareholder identifier.
func (s *LiftedShare[E, FE]) ID() sharing.ID {
	return s.id
}

// Value returns the lifted share's group-element vector.
func (s *LiftedShare[E, FE]) Value() []E {
	return s.v
}

// Equal reports whether two lifted shares have the same ID and group-element
// vector.
func (s *LiftedShare[E, FE]) Equal(other *LiftedShare[E, FE]) bool {
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

// MarshalCBOR serialises the lifted share to CBOR.
func (s *LiftedShare[E, FE]) MarshalCBOR() ([]byte, error) {
	dto := liftedShareDTO[E, FE]{
		ID: s.id,
		V:  s.v,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal lifted share")
	}
	return data, nil
}

// UnmarshalCBOR deserialises a lifted share from CBOR, validating the result.
func (s *LiftedShare[E, FE]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*liftedShareDTO[E, FE]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal lifted share")
	}
	ss, err := NewLiftedShare(dto.ID, dto.V...)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid lifted share data")
	}
	s.id = ss.id
	s.v = ss.v
	return nil
}
