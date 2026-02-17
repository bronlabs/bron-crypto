package additive

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/isn"
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
//   - shareholders: Set of shareholder IDs who will receive shares (all required for reconstruction)
func NewScheme[E GroupElement[E]](g Group[E], shareholders ds.Set[sharing.ID]) (*Scheme[E], error) {
	if shareholders == nil {
		return nil, ErrIsNil.WithMessage("identities is nil")
	}
	if g == nil {
		return nil, ErrIsNil.WithMessage("group is nil")
	}
	accessStructure, err := sharing.NewMinimalQualifiedAccessStructure(shareholders)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create access structure")
	}
	return &Scheme[E]{
		g:  g,
		ac: accessStructure,
	}, nil
}

// Scheme implements additive secret sharing over a finite group.
type Scheme[E GroupElement[E]] struct {
	g  Group[E]
	ac *sharing.MinimalQualifiedAccessStructure
}

// Name returns the canonical name of this scheme.
func (*Scheme[E]) Name() sharing.Name {
	return Name
}

// AccessStructure returns the access structure (all shareholders required).
func (d *Scheme[E]) AccessStructure() *sharing.MinimalQualifiedAccessStructure {
	return d.ac
}

// DealRandom generates shares for a randomly sampled secret.
func (d *Scheme[E]) DealRandom(prng io.Reader) (*DealerOutput[E], *Secret[E], error) {
	if prng == nil {
		return nil, nil, ErrIsNil.WithMessage("prng is nil")
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
		return nil, ErrIsNil.WithMessage("prng is nil")
	}
	if secret == nil {
		return nil, ErrIsNil.WithMessage("secret is nil")
	}
	isnSecret := isn.NewSecret(secret.Value())

	sharesList, err := isn.SumToSecret(isnSecret, d.g.Random, prng, d.ac.Shareholders().Size())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create shares using ISN")
	}
	shares := hashmap.NewComparable[sharing.ID, *Share[E]]()
	for i, id := range d.ac.Shareholders().Iter2() {
		shares.Put(id, &Share[E]{
			id: id,
			v:  sharesList[i],
		})
	}
	return &DealerOutput[E]{
		shares: shares.Freeze(),
	}, nil
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

	if !d.ac.IsAuthorized(ids...) {
		return nil, ErrFailed.WithMessage("not authorized to reconstruct secret with IDs %v", ids)
	}
	reconstructed := algebrautils.Sum(sharesSet[0], sharesSet[1:]...)
	return &Secret[E]{v: reconstructed.v}, nil
}

// NewShare creates a new additive share with the given ID and value.
// If an access structure is provided, validates that the ID is a valid shareholder.
func NewShare[E GroupElement[E]](id sharing.ID, v E, ac *sharing.MinimalQualifiedAccessStructure) (*Share[E], error) {
	if ac != nil && !ac.Shareholders().Contains(id) {
		return nil, ErrMembership.WithMessage("share ID %d is not a valid shareholder", id)
	}
	return &Share[E]{
		id: id,
		v:  v,
	}, nil
}

// Share represents an additive secret share consisting of a shareholder ID
// and a group element value.
type Share[E GroupElement[E]] struct {
	id sharing.ID
	v  E
}

// ID returns the shareholder identifier for this share.
func (s *Share[E]) ID() sharing.ID {
	return s.id
}

// Value returns the group element value of this share.
func (s *Share[E]) Value() E {
	return s.v
}

// Equal returns true if two shares have the same ID and value.
func (s *Share[E]) Equal(other *Share[E]) bool {
	if s == nil || other == nil {
		return s == other
	}
	return s.id == other.id && s.v.Equal(other.v)
}

// Op is an alias for Add, implementing the group element interface.
func (s *Share[E]) Op(other *Share[E]) *Share[E] {
	return s.Add(other)
}

// Add returns a new share that is the component-wise sum of two shares.
// Both shares must have the same ID.
func (s *Share[E]) Add(other *Share[E]) *Share[E] {
	return &Share[E]{
		id: s.id,
		v:  s.v.Op(other.v),
	}
}

// Clone returns a deep copy of this share.
func (s *Share[E]) Clone() *Share[E] {
	return &Share[E]{
		id: s.id,
		v:  s.v.Clone(),
	}
}

// HashCode returns a hash code for this share, for use in hash-based collections.
func (s *Share[E]) HashCode() base.HashCode {
	return base.HashCode(s.id) ^ s.v.HashCode()
}

// SchemeName returns the name of the secret sharing scheme.
func (*Share[E]) SchemeName() sharing.Name {
	return Name
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
