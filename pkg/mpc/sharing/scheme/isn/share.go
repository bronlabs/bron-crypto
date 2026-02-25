package isn

import (
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bitset"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
	"github.com/bronlabs/errs-go/errs"
)

// Share represents a shareholder's portion in an ISN secret sharing scheme.
// Each share contains a sparse map from clause identifiers (represented as
// bitsets of party IDs) to group elements. The map only stores non-identity
// values, making the representation space-efficient for large access structures.
//
// For CNF schemes, keys are maximal unqualified sets.
// Missing keys implicitly have the group identity value.
type Share[E algebra.GroupElement[E]] struct {
	id sharing.ID
	v  map[bitset.ImmutableBitSet[sharing.ID]]E
}

// ID returns the shareholder's unique identifier.
func (s *Share[E]) ID() sharing.ID {
	return s.id
}

// Value returns the share's sparse component map. Keys are clause identifiers
// (bitsets), and values are group elements. Missing keys implicitly represent
// the group identity element.
func (s *Share[E]) Value() ds.Map[bitset.ImmutableBitSet[sharing.ID], E] {
	return hashmap.NewComparableFromNativeLike(s.v).Freeze()
}

// Equal tests whether two shares are equal by comparing their IDs and
// all components of their value maps.
func (s *Share[E]) Equal(other *Share[E]) bool {
	if s == nil || other == nil {
		return s == other
	}
	if len(s.v) != len(other.v) {
		return false
	}
	for clause, si := range s.v {
		oi, exists := other.v[clause]
		if !exists || !si.Equal(oi) {
			return false
		}
	}
	return true
}

// Op performs a component-wise group operation on two shares, enabling
// additive homomorphism. Combines entries from both maps, treating missing
// keys as the group identity element.
func (s *Share[E]) Op(other *Share[E]) *Share[E] {
	result := make(map[bitset.ImmutableBitSet[sharing.ID]]E)

	// Combine all clauses from both shares
	allClauses := make(map[bitset.ImmutableBitSet[sharing.ID]]bool)
	for clause := range s.v {
		allClauses[clause] = true
	}
	for clause := range other.v {
		allClauses[clause] = true
	}

	for clause := range allClauses {
		sVal, sExists := s.v[clause]
		oVal, oExists := other.v[clause]

		if sExists && oExists {
			result[clause] = sVal.Op(oVal)
		}
	}

	return &Share[E]{
		id: s.id,
		v:  result,
	}
}

// HashCode computes a hash combining the share ID and all value components.
func (s *Share[E]) HashCode() base.HashCode {
	c := base.HashCode(s.id)
	for bi, si := range s.v {
		c = c.Combine(base.HashCode(bi), si.HashCode())
	}
	return c
}

// ToAdditive converts this CNF share to an additive share for the given minimal
// qualified access structure. This enables threshold-to-additive share conversion
// using Lagrange coefficients for MPC protocols.
//
// Currently unimplemented and will panic if called.
func (s *Share[E]) ToAdditive(to *accessstructures.Unanimity) (*additive.Share[E], error) {
	if s == nil {
		return nil, sharing.ErrIsNil.WithMessage("share is nil")
	}
	if to == nil {
		return nil, sharing.ErrIsNil.WithMessage("access structure is nil")
	}
	if !to.Shareholders().Contains(s.id) {
		return nil, sharing.ErrMembership.WithMessage("share ID %d is not in access structure", s.id)
	}

	shareValue := s.group().OpIdentity()
	for maxUnqualifiedSet, additiveShare := range s.v {
		p, err := pivot(maxUnqualifiedSet, to)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("no pivot for maximal unqualified set")
		}
		if p == s.id {
			shareValue = shareValue.Op(additiveShare)
		}
	}

	share, err := additive.NewShare(s.id, shareValue, to)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return share, nil
}

// ScalarOp performs scalar multiplication on the share by applying the scalar
// to each component in the sparse map. This enables linear operations on shares,
// such as computing linear combinations for MPC protocols.
//
// Parameters:
//   - scalar: The scalar value to multiply with each share component
//
// Returns a new share with all components scaled by the given scalar.
func (s *Share[E]) ScalarOp(scalar algebra.Numeric) *Share[E] {
	result := &Share[E]{
		id: s.id,
		v:  make(map[bitset.ImmutableBitSet[sharing.ID]]E),
	}
	for maxUnqualifiedSet, value := range s.v {
		result.v[maxUnqualifiedSet] = algebrautils.ScalarMul(value, scalar)
	}
	return result
}

// MarshalCBOR serialises the share.
func (s *Share[E]) MarshalCBOR() ([]byte, error) {
	dto := &shareDTO[E]{
		ID: s.id,
		V:  s.v,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal ISN Share")
	}
	return data, nil
}

// UnmarshalCBOR deserializes the share.
func (s *Share[E]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*shareDTO[E]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal ISN Share")
	}

	s.id = dto.ID
	s.v = dto.V
	return nil
}

func (s *Share[E]) group() algebra.Group[E] {
	v := algebra.StructureMustBeAs[algebra.Group[E]](slices.Collect(maps.Values(s.v))[0].Structure())
	return v
}

func pivot(unqualifiedSet bitset.ImmutableBitSet[sharing.ID], target *accessstructures.Unanimity) (sharing.ID, error) {
	sortedIds := target.Shareholders().List()
	slices.Sort(sortedIds)
	for _, id := range sortedIds {
		if !unqualifiedSet.Contains(id) {
			return id, nil
		}
	}

	return 0, sharing.ErrFailed.WithMessage("could not find pivot")
}

type shareDTO[E algebra.GroupElement[E]] struct {
	ID sharing.ID                               `cbor:"sharingID"`
	V  map[bitset.ImmutableBitSet[sharing.ID]]E `cbor:"value"`
}
