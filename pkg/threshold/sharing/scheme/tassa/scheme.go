package tassa

import (
	"io"
	"maps"
	"math"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/mathutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/scheme/additive"
	"github.com/bronlabs/errs-go/errs"
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
	accessStructure *accessstructures.HierarchicalConjunctiveThreshold
	field           algebra.PrimeField[F]
}

// NewScheme creates a Tassa scheme for the given hierarchical access structure
// and field, validating scheme-specific constraints.
func NewScheme[F algebra.PrimeFieldElement[F]](accessStructure *accessstructures.HierarchicalConjunctiveThreshold, field algebra.PrimeField[F]) (*Scheme[F], error) {
	if accessStructure == nil || field == nil {
		return nil, sharing.ErrIsNil.WithMessage("access structure or field is nil")
	}
	if err := checkConstraints(accessStructure, field); err != nil {
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

	// 2. Order Q increasingly: [i1, ..., in].
	slices.Sort(quorum)

	//   3. Build an n x n matrix M with entries:
	//     3.1 Let rank(id) be the threshold of the previous level containing id.
	//     3.2 Let phi(t, i, j) = (d^j/dx^j x^t) evaluated at x = i.
	//     3.3 Set M[r, c] = phi(c, ir, rank(ir)).
	m, err := s.buildMatrix(quorum)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not build matrix")
	}

	// 4. Compute d <- det(M); require d != 0.
	d := m.Determinant()
	if d.IsZero() {
		return nil, sharing.ErrMembership.WithMessage("unqualified set")
	}

	// 5. Set Y <- column vector [shares[i1], ..., shares[in]].
	shareValues := make([]F, len(quorum))
	for i, id := range quorum {
		shareValues[i] = sharesMap[id].value
	}

	// 6. Set M0 <- M with the first column replaced by Y.
	m0, err := m.SetColumn(0, shareValues)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not set column")
	}

	// 7. Compute d0 <- det(M0).
	d0 := m0.Determinant()

	// 8. Set s <- d0 / d.
	secretValue, err := d0.TryDiv(d)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not divide determinants during reconstruction")
	}
	secret = &Secret[F]{
		value: secretValue,
	}

	// 9. Return s.
	return secret, nil
}

// AccessStructure returns the hierarchical access policy used by the scheme.
func (s *Scheme[F]) AccessStructure() *accessstructures.HierarchicalConjunctiveThreshold {
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
func (s *Scheme[F]) ConvertShareToAdditive(share *Share[F], quorum *accessstructures.Unanimity) (*additive.Share[F], error) {
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
	var coeffs []F
	for _, i := range sortedQuorum {
		j, ok := s.rank(i)
		if !ok {
			return nil, sharing.ErrMembership.WithMessage("share ID %d does not belong to any level", i)
		}
		for t := range sortedQuorum {
			phi, err := s.phi(t, i, j)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("could not compute phi(t=%d, i=%d, j=%d)", t, i, j)
			}
			coeffs = append(coeffs, phi)
		}
	}
	matrices, err := mat.NewMatrixAlgebra(uint(len(sortedQuorum)), s.field)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create matrix algebra")
	}
	matrix, err := matrices.NewRowMajor(coeffs...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create matrix")
	}
	return matrix, nil
}

func (s *Scheme[F]) phi(t int, i sharing.ID, j int) (F, error) {
	zero := s.field.Zero()
	coeffs := make([]F, t+1)
	for c := 0; c < len(coeffs); c++ {
		coeffs[c] = s.field.Zero()
	}
	coeffs[len(coeffs)-1] = s.field.One()
	polys, err := polynomials.NewPolynomialRing(s.field)
	if err != nil {
		return zero, errs.Wrap(err).WithMessage("could not create polynomial ring")
	}
	poly, err := polys.New(coeffs...)
	if err != nil {
		return zero, errs.Wrap(err).WithMessage("could not create polynomial")
	}
	for range j {
		poly = poly.Derivative()
	}
	fi := s.field.FromUint64(uint64(i))
	return poly.Eval(fi), nil
}

func (s *Scheme[F]) rank(id sharing.ID) (int, bool) {
	r := 0
	for _, level := range s.accessStructure.Levels() {
		if level.Shareholders().Contains(id) {
			return r, true
		}
		r = level.Threshold()
	}
	return 0, false
}

func checkConstraints[F algebra.PrimeFieldElement[F]](ac *accessstructures.HierarchicalConjunctiveThreshold, field algebra.PrimeField[F]) error {
	// constraint 1: ids from lower level are strictly greater than ids from higher levels
	prevMax := sharing.ID(0)
	cummulativeIds := hashset.NewComparable[sharing.ID]()
	for _, level := range ac.Levels() {
		for id := range level.Shareholders().Iter() {
			if id <= prevMax {
				return sharing.ErrMembership.WithMessage("invalid shareholder ID %d", id)
			}
			cummulativeIds.Add(id)
		}
		allIds := cummulativeIds.List()
		slices.Sort(allIds)
		prevMax = allIds[len(allIds)-1]
	}

	// we increase n and k by one to accommodate "off by one error" caused by precision lost with float64
	n := uint64(prevMax) + 1
	k := uint64(ac.Levels()[len(ac.Levels())-1].Threshold()) + 1
	q, _ := field.Order().Big().Float64()

	// for k > 20, k! overflows uint64. Since we do not work with big enough fields to support such a big k anyway,
	// we reject.
	if k > 20 {
		// this will overflow factorial anyway
		return sharing.ErrFailed.WithMessage("too big threshold")
	}

	// constraint 3 (equation 35): α(k)N^((k−1)(k−2)/2) < q = |F| where α(k) := 2^(−k+2) ·(k−1)^((k−1)/2) ·(k−1)!
	alpha := math.Pow(2.0, 2.0-float64(k)) * math.Pow(float64(k-1), (float64(k)-1.0)/2.0) * float64(errs.Must1(mathutils.FactorialUint64(k-1)))
	if (alpha * math.Pow(float64(n), (float64(k)-1.0)*(float64(k)-2)/2.0)) >= q {
		return sharing.ErrFailed.WithMessage("constraint failed")
	}

	return nil
}
