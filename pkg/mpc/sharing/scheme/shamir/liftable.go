package shamir

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials/interpolation/lagrange"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
	"github.com/bronlabs/errs-go/errs"
)

type LiftableScheme[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	Scheme[FE]

	group algebra.PrimeGroup[E, FE]
}

func NewLiftableScheme[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]](primeGroup algebra.PrimeGroup[E, FE], accessStructure *accessstructures.Threshold) (*LiftableScheme[E, FE], error) {
	scalarField := algebra.StructureMustBeAs[algebra.PrimeField[FE]](primeGroup.ScalarStructure())
	shamirScheme, err := NewScheme(scalarField, accessStructure)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create underlying Shamir scheme")
	}

	return &LiftableScheme[E, FE]{
		group:  primeGroup,
		Scheme: *shamirScheme,
	}, nil
}

func (*LiftableScheme[E, FE]) LiftDealerFunc(df *DealerFunc[FE], basePoint E) (*LiftedDealerFunc[E, FE], error) {
	if df == nil {
		return nil, sharing.ErrIsNil.WithMessage("dealer func is nil")
	}
	if utils.IsNil(basePoint) {
		return nil, sharing.ErrIsNil.WithMessage("base point is nil")
	}
	liftedPoly, err := polynomials.LiftPolynomial(df.Polynomial(), basePoint)
	if err != nil {
		return nil, sharing.ErrIsNil.WithMessage("could not lift polynomial: %w", err)
	}
	return &LiftedDealerFunc[E, FE]{poly: liftedPoly}, nil
}

func (*LiftableScheme[E, FE]) LiftShare(share *Share[FE], basePoint E) (*LiftedShare[E, FE], error) {
	if share == nil {
		return nil, sharing.ErrIsNil.WithMessage("share is nil")
	}
	if utils.IsNil(basePoint) {
		return nil, sharing.ErrIsNil.WithMessage("base point is nil")
	}
	liftedValue := basePoint.ScalarOp(share.Value())
	out, err := NewLiftedShare(share.ID(), liftedValue)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to lift share to exponent")
	}
	return out, nil
}

func (*LiftableScheme[E, FE]) ConvertLiftedShareToAdditive(share *LiftedShare[E, FE], unanimity *accessstructures.Unanimity) (*additive.Share[E], error) {
	if share == nil {
		return nil, sharing.ErrIsNil.WithMessage("share is nil")
	}
	out, err := share.ToAdditive(unanimity)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to convert lifted share to additive share")
	}
	return out, nil
}

func (s *LiftableScheme[E, FE]) ReconstructInExponent(shares ...*LiftedShare[E, FE]) (*LiftedSecret[E, FE], error) {
	sharesSet := hashset.NewHashable(shares...)
	ids, err := sharing.CollectIDs(sharesSet.List()...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not collect IDs from shares")
	}
	if !s.ac.IsQualified(ids...) {
		return nil, sharing.ErrFailed.WithMessage("shares are not authorized by the access structure")
	}

	nodes := make([]FE, len(shares))
	values := make([]E, len(shares))
	for i, share := range sharesSet.Iter2() {
		nodes[i] = s.SharingIDToLagrangeNode(share.ID())
		values[i] = share.Value()
	}

	reconstructed, err := lagrange.InterpolateInExponentAt(s.group, nodes, values, s.f.Zero())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not interpolate polynomial in exponent")
	}
	return &LiftedSecret[E, FE]{
		v: reconstructed,
	}, nil
}
