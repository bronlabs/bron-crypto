package feldman

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/errs-go/errs"
)

func NewLiftedShare[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]](id sharing.ID, v []E) (*LiftedShare[E, FE], error) {
	if len(v) == 0 {
		return nil, sharing.ErrArgument.WithMessage("value cannot be empty")
	}

	return &LiftedShare[E, FE]{
		id: id,
		v:  v,
	}, nil
}

type LiftedShare[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	id sharing.ID
	v  []E
}

type liftedShareDTO[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	ID sharing.ID `cbor:"sharingID"`
	V  []E        `cbor:"value"`
}

func (s *LiftedShare[E, FE]) ID() sharing.ID {
	return s.id
}

func (s *LiftedShare[E, FE]) Value() []E {
	return s.v
}

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
