package additive

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/accessstructures"
	"github.com/bronlabs/errs-go/errs"
)

type (
	// Group is a finite group over which additive sharing can be performed.
	Group[E GroupElement[E]] algebra.FiniteGroup[E]
	// GroupElement is an element of a group that supports the group operation.
	GroupElement[E algebra.GroupElement[E]] algebra.GroupElement[E]
)

// Name is the canonical name of this secret sharing scheme.
const Name sharing.Name = "Additive Secret Sharing Scheme"

// NewScheme creates a new additive secret sharing scheme.
//
// Parameters:
//   - g: The group over which sharing is performed
//   - accessStructure: Unanimity access structure (all members are required for reconstruction)
func NewScheme[E GroupElement[E]](g Group[E], accessStructure *accessstructures.Unanimity) (*Scheme[E], error) {
	if g == nil {
		return nil, sharing.ErrIsNil.WithMessage("group is nil")
	}
	if accessStructure == nil {
		return nil, sharing.ErrIsNil.WithMessage("access structure is nil")
	}
	return &Scheme[E]{
		g:  g,
		ac: accessStructure,
	}, nil
}

// Scheme implements additive secret sharing over a finite group.
type Scheme[E GroupElement[E]] struct {
	g  Group[E]
	ac *accessstructures.Unanimity
}

// Name returns the canonical name of this scheme.
func (*Scheme[E]) Name() sharing.Name {
	return Name
}

// AccessStructure returns the access structure (all shareholders required).
func (d *Scheme[E]) AccessStructure() *accessstructures.Unanimity {
	return d.ac
}

// DealRandom generates shares for a randomly sampled secret.
func (d *Scheme[E]) DealRandom(prng io.Reader) (*DealerOutput[E], *Secret[E], error) {
	if prng == nil {
		return nil, nil, sharing.ErrIsNil.WithMessage("prng is nil")
	}
	value, err := d.g.Random(prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample group element")
	}
	secret := NewSecret(value)
	shares, err := d.Deal(secret, prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create shares")
	}
	return shares, secret, nil
}

// Deal creates shares for the given secret. All but one share are sampled randomly,
// and the final share is computed to ensure s_1 + s_2 + ... + s_n = s.
func (d *Scheme[E]) Deal(secret *Secret[E], prng io.Reader) (*DealerOutput[E], error) {
	if prng == nil {
		return nil, sharing.ErrIsNil.WithMessage("prng is nil")
	}
	if secret == nil {
		return nil, sharing.ErrIsNil.WithMessage("secret is nil")
	}
	sharesList, err := SumToSecret(secret.Value(), d.g.Random, prng, d.ac.Shareholders().Size())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create additive sharing of secret")
	}
	shares := hashmap.NewComparable[sharing.ID, *Share[E]]()
	for i, id := range d.ac.Shareholders().Iter2() {
		s, _ := NewShare(id, sharesList[i], d.ac)
		shares.Put(id, s)
	}
	return &DealerOutput[E]{
		shares: shares.Freeze(),
	}, nil
}

// SumToSecret samples l-1 random group elements and computes the final one so
// that all l shares sum to the provided secret.
func SumToSecret[E GroupElement[E]](secret E, sampler func(io.Reader) (E, error), prng io.Reader, l int) ([]E, error) {
	if utils.IsNil(secret) {
		return nil, sharing.ErrIsNil.WithMessage("secret is nil")
	}
	if sampler == nil {
		return nil, sharing.ErrIsNil.WithMessage("sampler is nil")
	}
	if prng == nil {
		return nil, sharing.ErrIsNil.WithMessage("prng is nil")
	}
	if l <= 0 {
		return nil, sharing.ErrFailed.WithMessage("number of shares must be positive")
	}

	group := algebra.StructureMustBeAs[algebra.Group[E]](secret.Structure())
	rs := make([]E, l)
	partial := group.OpIdentity()
	for j := range l - 1 {
		rj, err := sampler(prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not sample random group element")
		}
		rs[j] = rj
		partial = partial.Op(rj)
	}
	rs[l-1] = secret.Op(partial.OpInv())
	return rs, nil
}

// Reconstruct recovers the secret by summing all shares: s = s_1 + s_2 + ... + s_n.
// All shareholders must provide their shares for reconstruction to succeed.
func (d *Scheme[E]) Reconstruct(shares ...*Share[E]) (*Secret[E], error) {
	// First check for nil shares before creating hashset
	ids, err := sharing.CollectIDs(shares...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not collect IDs from shares")
	}

	// Filter out nil shares
	validShares := make([]*Share[E], 0, len(shares))
	for _, share := range shares {
		if share != nil {
			validShares = append(validShares, share)
		}
	}

	// Create set from valid shares only
	sharesSet := hashset.NewHashable(validShares...).List()

	if !d.ac.IsQualified(ids...) {
		return nil, sharing.ErrFailed.WithMessage("not authorized to reconstruct secret with IDs %v", ids)
	}
	reconstructed := algebrautils.Sum(sharesSet[0], sharesSet[1:]...)
	return &Secret[E]{v: reconstructed.Value()}, nil
}

type Share[E GroupElement[E]] = sharing.AdditiveShare[E]

func NewShare[E GroupElement[E]](id sharing.ID, v E, ac *accessstructures.Unanimity) (*Share[E], error) {
	if ac != nil && !ac.Shareholders().Contains(id) {
		return nil, sharing.ErrMembership.WithMessage("share ID %d is not a valid shareholder", id)
	}
	share, err := sharing.NewAdditiveShare(id, v)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create additive share")
	}
	return share, nil
}

// NewSecret creates a new secret from a group element.
func NewSecret[E GroupElement[E]](v E) *Secret[E] {
	return &Secret[E]{v: v}
}

// Secret wraps a group element that is being shared.
type Secret[E GroupElement[E]] struct {
	v E
}

// Value returns the underlying group element.
func (s *Secret[E]) Value() E {
	return s.v
}

// Equal returns true if two secrets have the same value.
func (s *Secret[E]) Equal(other *Secret[E]) bool {
	if s == nil || other == nil {
		return s == other
	}
	return s.v.Equal(other.v)
}

// Clone returns a deep copy of this secret.
func (s *Secret[E]) Clone() *Secret[E] {
	return &Secret[E]{
		v: s.v.Clone(),
	}
}

// DealerOutput contains the result of an additive dealing operation:
// a map from shareholder IDs to their corresponding shares.
type DealerOutput[E GroupElement[E]] struct {
	shares ds.Map[sharing.ID, *Share[E]]
}

// Shares returns the map of shareholder IDs to their corresponding shares.
func (d *DealerOutput[E]) Shares() ds.Map[sharing.ID, *Share[E]] {
	if d == nil {
		return nil
	}
	return d.shares
}
