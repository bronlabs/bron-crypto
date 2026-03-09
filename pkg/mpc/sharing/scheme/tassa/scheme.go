package tassa

import (
	"io"
	"maps"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials/interpolation/birkhoff"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/hierarchical"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
)

const (
	// Name is the human-readable identifier of the Tassa secret sharing scheme.
	Name = "Tassa Secret Sharing Scheme"
)

// Secret is a Tassa secret represented as a prime-field element.
type Secret[F algebra.PrimeFieldElement[F]] struct {
	value F
}

// NewSecret constructs a secret wrapper from a field element.
func NewSecret[F algebra.PrimeFieldElement[F]](value F) *Secret[F] {
	return &Secret[F]{
		value: value,
	}
}

// Equal reports whether two secrets are equal.
func (s *Secret[F]) Equal(r *Secret[F]) bool {
	if s == nil || r == nil {
		return s == r
	}

	return s.value.Equal(r.value)
}

// Value returns the underlying field element.
func (s *Secret[F]) Value() F {
	return s.value
}

// DealerOutput contains shares produced by one dealing execution.
type DealerOutput[F algebra.PrimeFieldElement[F]] struct {
	shares ds.Map[sharing.ID, *Share[F]]
}

// Shares returns the dealt shares indexed by shareholder ID.
func (do *DealerOutput[F]) Shares() ds.Map[sharing.ID, *Share[F]] {
	return do.shares
}

// Scheme implements Tassa hierarchical secret sharing over a prime field.
type Scheme[F algebra.PrimeFieldElement[F]] struct {
	accessStructure *hierarchical.HierarchicalConjunctiveThreshold
	field           algebra.PrimeField[F]
}

// NewScheme creates a Tassa scheme for the given hierarchical access structure
// and field, validating scheme-specific constraints.
func NewScheme[F algebra.PrimeFieldElement[F]](accessStructure *hierarchical.HierarchicalConjunctiveThreshold, field algebra.PrimeField[F]) (*Scheme[F], error) {
	if accessStructure == nil || field == nil {
		return nil, sharing.ErrIsNil.WithMessage("access structure or field is nil")
	}
	if err := hierarchical.CheckConstraints(accessStructure, field); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid access structure")
	}

	s := &Scheme[F]{
		accessStructure: accessStructure,
		field:           field,
	}
	return s, nil
}

// Name returns the scheme identifier.
func (*Scheme[F]) Name() sharing.Name {
	return Name
}

// Deal splits the provided secret into shares according to the hierarchical
// access structure.
func (s *Scheme[F]) Deal(secret *Secret[F], prng io.Reader) (*DealerOutput[F], error) {
	output, _, err := s.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not deal shares")
	}
	return output, nil
}

// DealRandom samples a random secret and splits it into shares.
func (s *Scheme[F]) DealRandom(prng io.Reader) (*DealerOutput[F], *Secret[F], error) {
	output, secret, _, err := s.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not deal random shares")
	}
	return output, secret, nil
}

// Reconstruct recovers the secret from a qualified set of shares.
func (s *Scheme[F]) Reconstruct(shares ...*Share[F]) (secret *Secret[F], err error) {
	// 1. Require Q is qualified under ac.
	if len(shares) < 2 {
		return nil, sharing.ErrArgument.WithMessage("at least two shares are required")
	}
	sharesMap := make(map[sharing.ID]*Share[F])
	for _, share := range shares {
		if share == nil {
			return nil, sharing.ErrIsNil.WithMessage("share is nil")
		}
		if _, exists := sharesMap[share.id]; exists {
			return nil, sharing.ErrMembership.WithMessage("duplicate share ID %d", share.id)
		}
		sharesMap[share.id] = share
	}
	quorum := slices.Collect(maps.Keys(sharesMap))
	if !s.AccessStructure().Shareholders().IsSuperSet(hashset.NewComparable(quorum...).Freeze()) ||
		!s.AccessStructure().IsQualified(quorum...) {

		return nil, sharing.ErrMembership.WithMessage("invalid quorum")
	}

	field := algebra.StructureMustBeAs[algebra.PrimeField[F]](shares[0].Value().Structure())
	var xs []F
	var js []uint64
	var ys []F
	for _, id := range quorum {
		xs = append(xs, field.FromUint64(uint64(id)))
		j, ok := s.accessStructure.Rank(id)
		if !ok {
			return nil, sharing.ErrFailed.WithMessage("invalid shareholder ID %d", id)
		}
		js = append(js, uint64(j))
		ys = append(ys, sharesMap[id].value)
	}
	poly, err := birkhoff.Interpolate(xs, js, ys)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not interpolate polynomial")
	}
	if poly.Degree() != s.accessStructure.Levels()[len(s.accessStructure.Levels())-1].Threshold()-1 {
		return nil, sharing.ErrMembership.WithMessage("reconstruction failed")
	}
	secretValue := poly.Coefficients()[0]
	return NewSecret(secretValue), nil
}

// AccessStructure returns the hierarchical access policy used by the scheme.
func (s *Scheme[F]) AccessStructure() *hierarchical.HierarchicalConjunctiveThreshold {
	return s.accessStructure
}

// DealAndRevealDealerFunc deals shares and returns the dealer polynomial used
// to generate them.
func (s *Scheme[F]) DealAndRevealDealerFunc(secret *Secret[F], prng io.Reader) (*DealerOutput[F], *polynomials.Polynomial[F], error) {
	if secret == nil || utils.IsNil(secret.value) {
		return nil, nil, sharing.ErrIsNil.WithMessage("secret is nil")
	}
	if prng == nil {
		return nil, nil, sharing.ErrIsNil.WithMessage("prng is nil")
	}

	// 1. Set k <- Tm - 1.
	degree := s.accessStructure.Levels()[len(s.AccessStructure().Levels())-1].Threshold() - 1

	// 2. Sample f(x), a random polynomial over F of degree k such that f(0) = s.
	polys, err := polynomials.NewPolynomialRing(s.field)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create polynomial ring")
	}
	dealerFunc, err := polys.RandomPolynomialWithConstantTerm(degree, secret.Value(), prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample dealer polynomial")
	}

	shares := hashmap.NewComparable[sharing.ID, *Share[F]]()

	// 3. Set d <- 0.
	d := 0

	// 4. For each level (Ti, Li) in ac order:
	for _, level := range s.AccessStructure().Levels() {
		// 4.1 Set g(x) <- d-th derivative of f(x).
		p := dealerFunc.Clone()
		for range d {
			p = p.Derivative()
		}

		// 4.2 For each id in Li, set shares[id] <- g(id).
		for id := range level.Shareholders().Iter() {
			shareValue := p.Eval(s.field.FromUint64(uint64(id)))
			shares.Put(id, &Share[F]{
				id:    id,
				value: shareValue,
			})
		}

		// 4.3 Set d <- Ti.
		d = level.Threshold()
	}

	// 5. Return shares.
	output := &DealerOutput[F]{
		shares: shares.Freeze(),
	}
	return output, dealerFunc, nil
}

// DealRandomAndRevealDealerFunc samples a random secret, deals shares, and
// returns the dealer polynomial used in the dealing.
func (s *Scheme[F]) DealRandomAndRevealDealerFunc(prng io.Reader) (*DealerOutput[F], *Secret[F], *polynomials.Polynomial[F], error) {
	if prng == nil {
		return nil, nil, nil, sharing.ErrIsNil.WithMessage("prng is nil")
	}

	secretValue, err := s.field.Random(prng)
	if err != nil {
		return nil, nil, nil, errs.Wrap(err).WithMessage("could not sample random secret")
	}
	secret := &Secret[F]{
		value: secretValue,
	}

	output, dealerFunc, err := s.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, nil, nil, errs.Wrap(err).WithMessage("could not create dealer func")
	}
	return output, secret, dealerFunc, nil
}

// ConvertShareToAdditive converts a Tassa share to an additive share over the
// provided quorum.
func (s *Scheme[F]) ConvertShareToAdditive(share *Share[F], quorum *unanimity.Unanimity) (*additive.Share[F], error) {
	if !quorum.Shareholders().Contains(share.id) {
		return nil, sharing.ErrMembership.WithMessage("share ID %d does not belong to quorum", share.id)
	}
	if !s.accessStructure.IsQualified(quorum.Shareholders().List()...) {
		return nil, sharing.ErrMembership.WithMessage("unqualified quorum")
	}

	sortedQuorum := quorum.Shareholders().List()
	slices.Sort(sortedQuorum)

	m, err := s.buildMatrix(sortedQuorum)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not build matrix")
	}
	d := m.Determinant()
	if d.IsZero() {
		return nil, sharing.ErrMembership.WithMessage("unqualified set")
	}

	idIdx := slices.Index(sortedQuorum, share.id)
	if idIdx < 0 {
		return nil, sharing.ErrMembership.WithMessage("share ID %d does not belong to quorum", share.id)
	}
	m0, err := m.Minor(idIdx, 0)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute minor")
	}
	d0 := m0.Determinant()
	d0 = d0.Mul(share.value)
	if idIdx%2 != 0 {
		d0 = d0.Neg()
	}

	shareValue, err := d0.TryDiv(d)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not divide determinants during reconstruction")
	}
	additiveShare, err := additive.NewShare(share.id, shareValue, quorum)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create additive share")
	}
	return additiveShare, nil
}

func (s *Scheme[F]) buildMatrix(sortedQuorum []sharing.ID) (*mat.SquareMatrix[F], error) {
	var eyes []F
	var jays []uint64
	for _, id := range sortedQuorum {
		eyes = append(eyes, s.field.FromUint64(uint64(id)))
		j, ok := s.accessStructure.Rank(id)
		if !ok {
			return nil, sharing.ErrFailed.WithMessage("invalid shareholder ID %d", id)
		}
		jays = append(jays, uint64(j))
	}
	m, err := birkhoff.BuildVandermondeMatrix(eyes, jays, len(eyes))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create birkhoff matrix")
	}
	out, err := m.AsSquare()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not convert to square matrix")
	}
	return out, nil
}
