package feldman

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/scheme/additive"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/scheme/shamir"
	"github.com/bronlabs/errs-go/errs"
)

// Share is a Feldman VSS share, which is identical to a Shamir share.
// The share value is f(i) where f is the dealing polynomial and i is the shareholder ID.
type Share[FE algebra.PrimeFieldElement[FE]] = shamir.Share[FE]

// NewShare creates a new Feldman share with the given ID and value.
// If an access structure is provided, validates that the ID is a valid shareholder.
func NewShare[FE algebra.PrimeFieldElement[FE]](id sharing.ID, v FE, ac *sharing.ThresholdAccessStructure) (*Share[FE], error) {
	s, err := shamir.NewShare(id, v, ac)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create Feldman share")
	}
	return s, nil
}

// LiftedShare represents a share lifted to the exponent: g^{f(i)} where f(i) is
// the underlying Shamir share value. This is used when shares need to be verified
// or combined in the group rather than the field.
type LiftedShare[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	id sharing.ID
	v  E
}

type liftedShareDTO[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	ID sharing.ID `cbor:"sharingID"`
	V  E          `cbor:"value"`
}

// NewLiftedShare creates a new lifted share with the given ID and group element value.
func NewLiftedShare[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]](id sharing.ID, v E) (*LiftedShare[E, FE], error) {
	if utils.IsNil(v) {
		return nil, sharing.ErrIsNil.WithMessage("value is nil")
	}

	return &LiftedShare[E, FE]{
		id: id,
		v:  v,
	}, nil
}

// ID returns the shareholder identifier for this lifted share.
func (s *LiftedShare[E, FE]) ID() sharing.ID {
	return s.id
}

// Value returns the group element value g^{f(i)} of this lifted share.
func (s *LiftedShare[E, FE]) Value() E {
	return s.v
}

// ToAdditive converts this lifted share to an additive share by exponentiating
// with the appropriate Lagrange coefficient. For shareholder i in qualified set S,
// the result is g^{λ_i · f(i)} where λ_i is the Lagrange coefficient.
// The resulting additive shares can be multiplied together to reconstruct g^s.
func (s *LiftedShare[E, FE]) ToAdditive(qualifiedSet *sharing.UnanimityAccessStructure) (*additive.Share[E], error) {
	if qualifiedSet == nil {
		return nil, sharing.ErrIsNil.WithMessage("qualified set is nil")
	}
	if !qualifiedSet.Shareholders().Contains(s.id) {
		return nil, sharing.ErrMembership.WithMessage("share ID %d is not a valid shareholder", s.id)
	}
	group := algebra.StructureMustBeAs[algebra.PrimeGroup[E, FE]](s.v.Structure())
	sf := algebra.StructureMustBeAs[algebra.PrimeField[FE]](group.ScalarStructure())
	lambdas, err := shamir.LagrangeCoefficients(sf, qualifiedSet.Shareholders().List()...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute Lagrange coefficients")
	}
	lambdaI, exists := lambdas.Get(s.id)
	if !exists {
		return nil, sharing.ErrMembership.WithMessage("share ID %d is not a valid shareholder", s.id)
	}
	converted := s.v.ScalarOp(lambdaI)
	additiveShare, err := additive.NewShare(s.id, converted, qualifiedSet)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to convert Feldman share to additive")
	}
	return additiveShare, nil
}

func (s *LiftedShare[E, FE]) MarshalCBOR() ([]byte, error) {
	dto := &liftedShareDTO[E, FE]{
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
		return err
	}
	s2, err := NewLiftedShare(dto.ID, dto.V)
	if err != nil {
		return err
	}
	*s = *s2
	return nil
}

// SharesInExponent is a collection of lifted shares that can be used to
// reconstruct the secret in the exponent (i.e., g^s) without revealing s.
type SharesInExponent[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] []*LiftedShare[E, FE]

// ReconstructAsAdditive reconstructs g^s from a set of lifted shares using
// Lagrange interpolation in the exponent. Each share g^{f(i)} is raised to
// its Lagrange coefficient λ_i, and the results are multiplied together:
// g^s = ∏_i (g^{f(i)})^{λ_i} = g^{∑_i λ_i·f(i)} = g^{f(0)} = g^s.
func (s SharesInExponent[E, FE]) ReconstructAsAdditive() (E, error) {
	if len(s) == 0 {
		return *new(E), sharing.ErrArgument.WithMessage("no shares provided for reconstruction")
	}

	group := algebra.StructureMustBeAs[algebra.PrimeGroup[E, FE]](s[0].v.Structure())
	sf := algebra.StructureMustBeAs[algebra.PrimeField[FE]](group.ScalarStructure())
	qualifiedSet, err := sharing.NewUnanimityAccessStructure(
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
		return *new(E), errs.Wrap(err).WithMessage("could not create qualified set from shares")
	}
	lambdas, err := shamir.LagrangeCoefficients(sf, qualifiedSet.Shareholders().List()...)
	if err != nil {
		return *new(E), errs.Wrap(err).WithMessage("could not compute Lagrange coefficients")
	}
	converted := make([]*additive.Share[E], 0, len(s))
	for _, share := range s {
		lambdaI, exists := lambdas.Get(share.ID())
		if !exists {
			return *new(E), sharing.ErrMembership.WithMessage("share ID %d is not a valid shareholder", share.ID())
		}
		si, err := additive.NewShare(share.ID(), share.v.ScalarOp(lambdaI), nil)
		if err != nil {
			return *new(E), errs.Wrap(err).WithMessage("could not create additive share from share in exponent")
		}
		converted = append(converted, si)
	}
	additiveScheme, err := additive.NewScheme(group, qualifiedSet)
	if err != nil {
		return *new(E), errs.Wrap(err).WithMessage("could not create additive scheme")
	}
	reconstructed, err := additiveScheme.Reconstruct(converted...)
	if err != nil {
		return *new(E), errs.Wrap(err).WithMessage("could not reconstruct additive share")
	}
	return reconstructed.Value(), nil
}
