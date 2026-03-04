package shamir

import (
	"encoding/binary"
	"iter"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
	"github.com/bronlabs/errs-go/errs"
)

// Share represents a Shamir secret share, consisting of an evaluation point (ID)
// and the polynomial value at that point.
type Share[FE algebra.PrimeFieldElement[FE]] struct {
	id sharing.ID
	v  FE
}

type shareDTO[FE algebra.PrimeFieldElement[FE]] struct {
	ID sharing.ID `cbor:"sharingID"`
	V  FE         `cbor:"value"`
}

// NewShare creates a new Shamir share with the given ID and value.
// If an access structure is provided, validates that the ID is a valid shareholder.
func NewShare[FE algebra.PrimeFieldElement[FE]](id sharing.ID, value FE, ac *accessstructures.Threshold) (*Share[FE], error) {
	if ac != nil && !ac.Shareholders().Contains(id) {
		return nil, sharing.ErrMembership.WithMessage("share ID %d is not a valid shareholder", id)
	}
	return &Share[FE]{
		id: id,
		v:  value,
	}, nil
}

// ToAdditive converts this Shamir share to an additive share by multiplying
// by the appropriate Lagrange coefficient. The resulting additive shares can
// be summed to reconstruct the secret.
func (s *Share[FE]) ToAdditive(qualifiedSet *accessstructures.Unanimity) (*additive.Share[FE], error) {
	field, ok := s.v.Structure().(algebra.PrimeField[FE])
	if !ok {
		return nil, sharing.ErrType.WithMessage("share value does not implement Field interface")
	}
	lambdas, err := LagrangeCoefficients(field, qualifiedSet.Shareholders().List()...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute Lagrange coefficients")
	}
	lambdaI, exists := lambdas.Get(s.id)
	if !exists {
		return nil, sharing.ErrMembership.WithMessage("share ID %d is not a valid shareholder", s.id)
	}
	converted := lambdaI.Mul(s.v)
	additiveShare, err := additive.NewShare(s.id, converted, qualifiedSet)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to convert Shamir share to additive")
	}
	return additiveShare, nil
}

// ID returns the shareholder identifier for this share.
func (s *Share[_]) ID() sharing.ID {
	return s.id
}

// Value returns the share value (the polynomial evaluation at ID).
func (s *Share[FE]) Value() FE {
	return s.v
}

// Repr returns an iterator that yields the share's single value component.
func (s *Share[FE]) Repr() iter.Seq[FE] {
	return func(yield func(FE) bool) {
		yield(s.v)
	}
}

// Equal returns true if two shares have the same ID and value.
func (s *Share[FE]) Equal(other *Share[FE]) bool {
	if s == nil || other == nil {
		return s == other
	}
	return s.id == other.id && s.v.Equal(other.v)
}

// Op is an alias for Add, implementing the group element interface.
func (s *Share[FE]) Op(other *Share[FE]) *Share[FE] {
	return s.Add(other)
}

// Add returns a new share that is the component-wise sum of two shares.
// Both shares must have the same ID.
func (s *Share[FE]) Add(other *Share[FE]) *Share[FE] {
	if s.id != other.id {
		panic("cannot add shares with different IDs")
	}
	return &Share[FE]{
		id: s.id,
		v:  s.v.Add(other.v),
	}
}

// SubPlain subtracts a plaintext value from this share.
func (s *Share[FE]) SubPlain(other FE) *Share[FE] {
	return &Share[FE]{
		id: s.id,
		v:  s.v.Sub(other),
	}
}

// ScalarOp is an alias for ScalarMul.
func (s *Share[FE]) ScalarOp(scalar algebra.Numeric) *Share[FE] {
	return s.ScalarMul(scalar)
}

// ScalarMul returns a new share with the value multiplied by a scalar.
func (s *Share[FE]) ScalarMul(scalar algebra.Numeric) *Share[FE] {
	return &Share[FE]{
		id: s.id,
		v:  algebrautils.ScalarMul(s.v, scalar),
	}
}

// Clone returns a deep copy of this share.
func (s *Share[FE]) Clone() *Share[FE] {
	return &Share[FE]{
		id: s.id,
		v:  s.v.Clone(),
	}
}

// HashCode returns a hash code for this share, for use in hash-based collections.
func (s *Share[FE]) HashCode() base.HashCode {
	return base.HashCode(s.id).Combine(s.v.HashCode())
}

// Bytes returns the canonical byte representation of this share.
func (s *Share[FE]) Bytes() []byte {
	buf := s.Value().Bytes()
	binary.BigEndian.AppendUint64(buf, uint64(s.ID()))
	return buf
}

// MarshalCBOR serialises the share.
func (s *Share[FE]) MarshalCBOR() ([]byte, error) {
	dto := &shareDTO[FE]{
		ID: s.id,
		V:  s.v,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal Shamir Share")
	}
	return data, nil
}

// UnmarshalCBOR deserializes the share.
func (s *Share[FE]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*shareDTO[FE]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal Shamir Share")
	}

	s2, err := NewShare(dto.ID, dto.V, nil)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create Shamir Share from DTO")
	}
	*s = *s2
	return nil
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
	if id == 0 {
		return nil, sharing.ErrIsZero.WithMessage("share ID cannot be zero")
	}
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

func (s *LiftedShare[E, FE]) Op(other *LiftedShare[E, FE]) *LiftedShare[E, FE] {
	if s.id != other.id {
		panic("cannot add shares with different IDs")
	}
	return &LiftedShare[E, FE]{
		id: s.id,
		v:  s.v.Op(other.v),
	}
}

func (s *LiftedShare[E, FE]) ScalarOp(scalar algebra.Numeric) *LiftedShare[E, FE] {
	return &LiftedShare[E, FE]{
		id: s.id,
		v:  algebrautils.ScalarMul(s.v, scalar),
	}
}

// ToAdditive converts this lifted share to an additive share by exponentiating
// with the appropriate Lagrange coefficient. For shareholder i in qualified set S,
// the result is g^{λ_i · f(i)} where λ_i is the Lagrange coefficient.
// The resulting additive shares can be multiplied together to reconstruct g^s.
func (s *LiftedShare[E, FE]) ToAdditive(qualifiedSet *accessstructures.Unanimity) (*additive.Share[E], error) {
	if qualifiedSet == nil {
		return nil, sharing.ErrIsNil.WithMessage("qualified set is nil")
	}
	if !qualifiedSet.Shareholders().Contains(s.id) {
		return nil, sharing.ErrMembership.WithMessage("share ID %d is not a valid shareholder", s.id)
	}
	group := algebra.StructureMustBeAs[algebra.PrimeGroup[E, FE]](s.v.Structure())
	sf := algebra.StructureMustBeAs[algebra.PrimeField[FE]](group.ScalarStructure())
	lambdas, err := LagrangeCoefficients(sf, qualifiedSet.Shareholders().List()...)
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

// MarshalCBOR serialises the lifted share.
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

// Equal returns true if two lifted shares have the same ID and value.
func (s *LiftedShare[E, FE]) Equal(other *LiftedShare[E, FE]) bool {
	if s == nil || other == nil {
		return s == other
	}
	return s.id == other.id && s.v.Equal(other.v)
}

// HashCode returns a hash code for this lifted share.
func (s *LiftedShare[E, FE]) HashCode() base.HashCode {
	return base.HashCode(s.id).Combine(s.v.HashCode())
}

// Repr returns an iterator that yields the lifted share's single group element value.
func (s *LiftedShare[E, FE]) Repr() iter.Seq[E] {
	return func(yield func(E) bool) {
		yield(s.v)
	}
}

// UnmarshalCBOR deserializes the lifted share.
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
	qualifiedSet, err := accessstructures.NewUnanimityAccessStructure(
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
	lambdas, err := LagrangeCoefficients(sf, qualifiedSet.Shareholders().List()...)
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
