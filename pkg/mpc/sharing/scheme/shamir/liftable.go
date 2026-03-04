package shamir

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
	"github.com/bronlabs/errs-go/errs"
)

type LiftableScheme[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	Scheme[FE]
}

func NewLiftableScheme[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]](primeGroup algebra.PrimeGroup[E, FE], accessStructure *accessstructures.Threshold) (*LiftableScheme[E, FE], error) {
	scalarField := algebra.StructureMustBeAs[algebra.PrimeField[FE]](primeGroup.ScalarStructure())
	shamirScheme, err := NewScheme(scalarField, accessStructure)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create underlying Shamir scheme")
	}

	return &LiftableScheme[E, FE]{
		Scheme: *shamirScheme,
	}, nil
}

func (s *LiftableScheme[E, FE]) LiftDealerFunc(df *DealerFunc[FE], basePoint E) (*LiftedDealerFunc[E, FE], error) {
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

func (s *LiftableScheme[E, FE]) LiftShare(share *Share[FE], basePoint E) (*LiftedShare[E, FE], error) {
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

func (s *LiftableScheme[E, FE]) ConvertLiftedShareToAdditive(share *LiftedShare[E, FE], unanimity *accessstructures.Unanimity) (*additive.Share[E], error) {
	if share == nil {
		return nil, sharing.ErrIsNil.WithMessage("share is nil")
	}
	out, err := share.ToAdditive(unanimity)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to convert lifted share to additive share")
	}
	return out, nil
}
