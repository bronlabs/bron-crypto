package feldman

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	"github.com/fxamacker/cbor/v2"
)

type Share[FE algebra.PrimeFieldElement[FE]] = shamir.Share[FE]

func NewShare[FE algebra.PrimeFieldElement[FE]](id sharing.ID, v FE, ac *AccessStructure) (*Share[FE], error) {
	return shamir.NewShare(id, v, ac)
}

type LiftedShare[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	id sharing.ID
	v  E
}

type liftedShareDTO[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	ID sharing.ID `cbor:"1"`
	V  E          `cbor:"2"`
}

func NewLiftedShare[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]](id sharing.ID, v E) (*LiftedShare[E, FE], error) {
	if utils.IsNil(v) {
		return nil, errs.NewIsNil("value is nil")
	}

	return &LiftedShare[E, FE]{
		id: id,
		v:  v,
	}, nil
}

func (s *LiftedShare[E, FE]) ID() sharing.ID {
	return s.id
}

func (s *LiftedShare[E, FE]) Value() E {
	return s.v
}

func (s *LiftedShare[E, FE]) ToAdditive(qualifiedSet *sharing.MinimalQualifiedAccessStructure) (*additive.Share[E], error) {
	if qualifiedSet == nil {
		return nil, errs.NewIsNil("qualified set is nil")
	}
	if !qualifiedSet.Shareholders().Contains(s.id) {
		return nil, errs.NewMembership("share ID %d is not a valid shareholder", s.id)
	}
	group := algebra.StructureMustBeAs[algebra.PrimeGroup[E, FE]](s.v.Structure())
	sf := algebra.StructureMustBeAs[algebra.PrimeField[FE]](group.ScalarStructure())
	lambdas, err := shamir.LagrangeCoefficients(sf, qualifiedSet.Shareholders().List()...)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute Lagrange coefficients")
	}
	lambda_i, exists := lambdas.Get(s.id)
	if !exists {
		return nil, errs.NewMembership("share ID %d is not a valid shareholder", s.id)
	}
	converted := s.v.ScalarOp(lambda_i)
	return additive.NewShare(s.id, converted, qualifiedSet)
}

func (s *LiftedShare[E, FE]) MarshalCBOR() ([]byte, error) {
	dto := &liftedShareDTO[E, FE]{
		ID: s.id,
		V:  s.v,
	}
	return cbor.Marshal(dto)
}

func (s *LiftedShare[E, FE]) UnmarshalCBOR(data []byte) error {
	var dto liftedShareDTO[E, FE]
	if err := cbor.Unmarshal(data, &dto); err != nil {
		return err
	}
	s2, err := NewLiftedShare(dto.ID, dto.V)
	if err != nil {
		return err
	}
	*s = *s2
	return nil
}

type SharesInExponent[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] []*LiftedShare[E, FE]

func (s SharesInExponent[E, FE]) ReconstructAsAdditive() (E, error) {
	if len(s) == 0 {
		return *new(E), errs.NewArgument("no shares provided for reconstruction")
	}

	group := algebra.StructureMustBeAs[algebra.PrimeGroup[E, FE]](s[0].v.Structure())
	sf := algebra.StructureMustBeAs[algebra.PrimeField[FE]](group.ScalarStructure())
	qualifiedSet, err := sharing.NewMinimalQualifiedAccessStructure(
		hashset.NewComparable(
			slices.Collect(
				iterutils.Map(
					slices.Values(s),
					func(share *LiftedShare[E, FE]) sharing.ID { return share.ID() },
				),
			)...,
		).Freeze(),
	)
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not create qualified set from shares")
	}
	lambdas, err := shamir.LagrangeCoefficients(sf, qualifiedSet.Shareholders().List()...)
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not compute Lagrange coefficients")
	}
	converted := make([]*additive.Share[E], 0, len(s))
	for _, share := range s {
		lambda_i, exists := lambdas.Get(share.ID())
		if !exists {
			return *new(E), errs.NewMembership("share ID %d is not a valid shareholder", share.ID())
		}
		si, err := additive.NewShare(share.ID(), share.v.ScalarOp(lambda_i), nil)
		if err != nil {
			return *new(E), errs.WrapFailed(err, "could not create additive share from share in exponent")
		}
		converted = append(converted, si)
	}
	additiveScheme, err := additive.NewScheme(group, qualifiedSet.Shareholders())
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not create additive scheme")
	}
	reconstructed, err := additiveScheme.Reconstruct(converted...)
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not reconstruct additive share")
	}
	return reconstructed.Value(), nil
}
