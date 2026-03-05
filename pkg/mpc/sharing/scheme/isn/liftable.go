package isn

import (
	"maps"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bitset"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
	"github.com/bronlabs/errs-go/errs"
)

type LiftableScheme[
	E algebra.ModuleElement[E, S], S algebra.RingElement[S],
] struct {
	module algebra.Module[E, S]
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
		module: g,
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

func (s *LiftableScheme[E, S]) ReconstructInExponent(shares ...*LiftedShare[E]) (*LiftedSecret[E, S], error) {
	ids, err := sharing.CollectIDs(shares...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not collect IDs from shares")
	}
	if !s.ac.IsQualified(ids...) {
		return nil, sharing.ErrUnauthorized.WithMessage("not authorized to reconstruct secret with IDs %v", ids)
	}

	chunks := make(map[bitset.ImmutableBitSet[sharing.ID]]E)
	for _, share := range shares {
		if share == nil {
			return nil, sharing.ErrFailed.WithMessage("nil share provided")
		}

		for _, maxUnqualifiedSet := range s.clauses {
			if maxUnqualifiedSet.Contains(share.id) {
				continue
			}

			chunk, ok := share.v[maxUnqualifiedSet]
			if !ok || utils.IsNil(chunk) {
				return nil, sharing.ErrFailed.WithMessage("share for ID %d does not contain piece for maximal unqualified set %v", share.id, maxUnqualifiedSet.List())
			}
			if refChunk, contains := chunks[maxUnqualifiedSet]; contains {
				if !refChunk.Equal(chunk) {
					return nil, sharing.ErrFailed.WithMessage("inconsistent shares")
				}
			} else {
				chunks[maxUnqualifiedSet] = chunk
			}
		}
	}

	reconstructed := iterutils.Reduce(maps.Values(chunks), s.module.OpIdentity(), E.Op)
	return NewLiftedSecret(reconstructed), nil
}
