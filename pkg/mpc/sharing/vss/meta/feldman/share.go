package feldman

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/errs-go/errs"
)

// NewLiftedShare creates a lifted share for the given shareholder with the
// provided group-element vector — one entry per MSP row owned by that
// shareholder. The lifted share represents [λ_i]G, the group-element
// counterpart of the scalar share λ_i.
func NewLiftedShare[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]](id sharing.ID, v []E) (*LiftedShare[E, FE], error) {
	if len(v) == 0 {
		return nil, sharing.ErrArgument.WithMessage("value cannot be empty")
	}

	return &LiftedShare[E, FE]{
		id: id,
		v:  v,
	}, nil
}

// LiftedShare is a share lifted into the group: each scalar component λ_i,j
// is replaced by [λ_i,j]G. For ideal MSPs (one row per shareholder) the
// vector has length one. Lifted shares are used in protocols that operate
// in the exponent, such as threshold signing, where the secret itself is
// never reconstructed in the clear.
type LiftedShare[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	id sharing.ID
	v  []E
}

type liftedShareDTO[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	ID sharing.ID `cbor:"sharingID"`
	V  []E        `cbor:"value"`
}

// ID returns the shareholder identifier.
func (s *LiftedShare[E, FE]) ID() sharing.ID {
	return s.id
}

// Value returns the group-element vector [λ_i]G.
func (s *LiftedShare[E, FE]) Value() []E {
	return s.v
}

// MarshalCBOR serialises the lifted share to CBOR.
func (s *LiftedShare[E, FE]) MarshalCBOR() ([]byte, error) {
	dto := liftedShareDTO[E, FE]{
		ID: s.id,
		V:  s.v,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal Feldman LiftedShare")
	}
	return data, nil
}

// UnmarshalCBOR deserialises a lifted share from CBOR.
func (s *LiftedShare[E, FE]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*liftedShareDTO[E, FE]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal Feldman LiftedShare")
	}
	s2, err := NewLiftedShare(dto.ID, dto.V)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create Feldman LiftedShare from DTO")
	}
	*s = *s2
	return nil
}
