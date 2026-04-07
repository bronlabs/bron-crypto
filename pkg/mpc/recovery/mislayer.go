package recovery

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

// Mislayer represents the party whose share is being reconstructed.
type Mislayer[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	ctx    *session.Context
	field  algebra.PrimeField[S]
	scheme *feldman.Scheme[G, S]
	round  network.Round
}

// NewMislayer constructs a mislayer helper used to validate and interpolate recovered shares.
func NewMislayer[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](ctx *session.Context, as *threshold.Threshold, group algebra.PrimeGroup[G, S]) (*Mislayer[G, S], error) {
	if ctx == nil || as == nil || group == nil {
		return nil, ErrInvalidArgument.WithMessage("invalid arguments")
	}

	if !ctx.Quorum().IsSubSet(as.Shareholders()) {
		return nil, ErrInvalidArgument.WithMessage("access structure doesn't match context")
	}
	if !as.IsQualified(ctx.Quorum().List()...) {
		return nil, ErrInvalidArgument.WithMessage("recovery quorum is not qualified for the access structure")
	}

	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
	scheme, err := feldman.NewScheme(group.Generator(), as)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create feldman scheme")
	}

	m := &Mislayer[G, S]{
		ctx:    ctx,
		field:  field,
		scheme: scheme,
		round:  3,
	}
	return m, nil
}

// SharingID returns the identifier of the share being recovered.
func (m *Mislayer[G, S]) SharingID() sharing.ID {
	return m.ctx.HolderID()
}
