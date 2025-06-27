package additive

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

type (
	Group[E GroupElement[E]] interface {
		algebra.Group[E]
		algebra.FiniteStructure[E]
	}
	GroupElement[E algebra.GroupElement[E]] algebra.GroupElement[E]
)

const Name sharing.Name = "Additive Secret Sharing Scheme"

func NewScheme[E GroupElement[E]](g Group[E], shareholders ds.Set[sharing.ID]) (*Scheme[E], error) {
	if shareholders == nil {
		return nil, errs.NewIsNil("identities is nil")
	}
	if g == nil {
		return nil, errs.NewIsNil("group is nil")
	}
	accessStructure, err := sharing.NewMinimalQualifiedAccessStructure(shareholders)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create access structure")
	}
	return &Scheme[E]{
		g:  g,
		ac: accessStructure,
	}, nil
}

type Scheme[E GroupElement[E]] struct {
	g  Group[E]
	ac *sharing.MinimalQualifiedAccessStructure
}

func (d *Scheme[E]) Name() sharing.Name {
	return Name
}

func (d *Scheme[E]) AccessStructure() *sharing.MinimalQualifiedAccessStructure {
	return d.ac
}

func (d *Scheme[E]) DealRandom(prng io.Reader) (*DealerOutput[E], *Secret[E], error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng is nil")
	}
	value, err := d.g.Random(prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "could not sample group element")
	}
	secret := NewSecret(value)
	shares, err := d.Deal(secret, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create shares")
	}
	return shares, secret, nil
}

func (d *Scheme[E]) Deal(secret *Secret[E], prng io.Reader) (*DealerOutput[E], error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	if secret == nil {
		return nil, errs.NewIsNil("secret is nil")
	}
	participantsList := d.ac.Shareholders().List()
	shares := hashmap.NewComparable[sharing.ID, *Share[E]]()

	partialSum := d.g.OpIdentity()
	for _, id := range participantsList[1:] {
		v, err := d.g.Random(prng)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "could not sample group element")
		}
		partialSum = partialSum.Op(v)
		shares.Put(id, &Share[E]{
			id: id,
			v:  v,
		})
	}
	final := secret.Value().Op(partialSum.OpInv())
	shares.Put(participantsList[0], &Share[E]{
		id: participantsList[0],
		v:  final,
	})
	return &DealerOutput[E]{
		shares: shares.Freeze(),
	}, nil
}

func (d *Scheme[E]) Reconstruct(shares ...*Share[E]) (*Secret[E], error) {
	// First check for nil shares before creating hashset
	ids, err := sharing.CollectIDs(shares...)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not collect IDs from shares")
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
		return nil, errs.NewFailed("not authorized to reconstruct secret with IDs %v", ids)
	}
	reconstructed := algebrautils.Sum(sharesSet[0], sharesSet[1:]...)
	return &Secret[E]{v: reconstructed.v}, nil
}

func NewShare[E GroupElement[E]](id sharing.ID, v E, ac *sharing.MinimalQualifiedAccessStructure) (*Share[E], error) {
	if ac != nil && !ac.Shareholders().Contains(id) {
		return nil, errs.NewMembership("share ID %d is not a valid shareholder", id)
	}
	return &Share[E]{
		id: id,
		v:  v,
	}, nil
}

type Share[E GroupElement[E]] struct {
	id sharing.ID
	v  E
}

func (s *Share[E]) ID() sharing.ID {
	return s.id
}

func (s *Share[E]) Value() E {
	return s.v
}

func (s *Share[E]) Equal(other *Share[E]) bool {
	if s == nil || other == nil {
		return s == other
	}
	return s.id == other.id && s.v.Equal(other.v)
}

func (s *Share[E]) Op(other *Share[E]) *Share[E] {
	return s.Add(other)
}

func (s *Share[E]) Add(other *Share[E]) *Share[E] {
	return &Share[E]{
		id: s.id,
		v:  s.v.Op(other.v),
	}
}

func (s *Share[E]) Clone() *Share[E] {
	return &Share[E]{
		id: s.id,
		v:  s.v.Clone(),
	}
}

func (s *Share[E]) HashCode() base.HashCode {
	return base.HashCode(s.id) ^ s.v.HashCode()
}

func (*Share[E]) SchemeName() sharing.Name {
	return Name
}

func NewSecret[E GroupElement[E]](v E) *Secret[E] {
	return &Secret[E]{v: v}
}

type Secret[E GroupElement[E]] struct {
	v E
}

func (s *Secret[E]) Value() E {
	return s.v
}

func (s *Secret[E]) Equal(other *Secret[E]) bool {
	if s == nil || other == nil {
		return s == other
	}
	return s.v.Equal(other.v)
}

func (s *Secret[E]) Clone() *Secret[E] {
	return &Secret[E]{
		v: s.v.Clone(),
	}
}

type DealerOutput[E GroupElement[E]] struct {
	shares ds.Map[sharing.ID, *Share[E]]
}

func (d *DealerOutput[E]) Shares() ds.Map[sharing.ID, *Share[E]] {
	if d == nil {
		return nil
	}
	return d.shares
}

func _[G Group[E], E GroupElement[E]]() {
	var (
		_ sharing.AdditiveShare[*Share[E], E, *sharing.MinimalQualifiedAccessStructure] = (*Share[E])(nil)
		_ sharing.AdditivelyShareableSecret[*Secret[E], E]                              = (*Secret[E])(nil)

		_ sharing.AdditiveSSS[*Share[E], E, *Secret[E], E, *DealerOutput[E], *sharing.MinimalQualifiedAccessStructure] = (*Scheme[E])(nil)
	)
}
