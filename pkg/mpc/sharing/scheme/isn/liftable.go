package isn

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bitset"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
	"github.com/bronlabs/errs-go/errs"
)

type LiftableScheme[
	E algebra.ModuleElement[E, S], S algebra.RingElement[S],
] struct {
	Scheme[S]
}

func NewFiniteLiftableScheme[
	E algebra.ModuleElement[E, S], S algebra.RingElement[S],
](g algebra.FiniteModule[E, S], ac accessstructures.Monotone) (*LiftableScheme[E, S], error) {
	scalarRing := algebra.StructureMustBeAs[algebra.FiniteRing[S]](g.ScalarStructure())
	scheme, err := NewFiniteScheme(scalarRing, ac)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create underlying ISN scheme")
	}
	return &LiftableScheme[E, S]{
		Scheme: *scheme,
	}, nil
}

func (s *LiftableScheme[E, S]) LiftDealerFunc(df DealerFunc[S], basePoint E) (LiftedDealerFunc[E, S], error) {
	if df == nil {
		return nil, sharing.ErrIsNil.WithMessage("dealer func is nil")
	}
	if utils.IsNil(basePoint) {
		return nil, sharing.ErrIsNil.WithMessage("base point is nil")
	}
	lifted := make(map[bitset.ImmutableBitSet[sharing.ID]]E, len(df))
	for clause, value := range df {
		lifted[clause] = basePoint.ScalarOp(value)
	}
	return LiftedDealerFunc[E, S](lifted), nil
}

func (s *LiftableScheme[E, S]) LiftShare(share *Share[S], basePoint E) (*LiftedShare[E], error) {
	if share == nil {
		return nil, sharing.ErrIsNil.WithMessage("share is nil")
	}
	if utils.IsNil(basePoint) {
		return nil, sharing.ErrIsNil.WithMessage("base point is nil")
	}
	vs := make(map[bitset.ImmutableBitSet[sharing.ID]]E, len(share.v))
	for clause, value := range share.v {
		vs[clause] = basePoint.ScalarOp(value)
	}
	out, err := NewLiftedShare(share.id, vs)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create lifted share")
	}
	return out, nil
}

func (s *LiftableScheme[E, S]) ConvertLiftedShareToAdditive(share *LiftedShare[E], unanimity *accessstructures.Unanimity) (*additive.Share[E], error) {
	if share == nil {
		return nil, sharing.ErrIsNil.WithMessage("share is nil")
	}
	return share.ToAdditive(unanimity)
}
