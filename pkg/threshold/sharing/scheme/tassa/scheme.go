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
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/scheme/additive"
	"github.com/bronlabs/errs-go/errs"
)

const (
	Name = "Tassa Secret Sharing Scheme"
)

func _[F algebra.PrimeFieldElement[F]]() {
	var _ sharing.PolynomialLSSS[*Share[F], F, *additive.Share[F], F, *Secret[F], F, *DealerOutput[F], F, *sharing.HierarchicalConjunctiveThresholdAccessStructure] = (*Scheme[F])(nil)
}

type Secret[F algebra.PrimeFieldElement[F]] struct {
	value F
}

func NewSecret[F algebra.PrimeFieldElement[F]](value F) *Secret[F] {
	return &Secret[F]{
		value: value,
	}
}

func (s *Secret[F]) Equal(r *Secret[F]) bool {
	if s == nil || r == nil {
		return s == r
	}

	return s.value.Equal(r.value)
}

func (s *Secret[F]) Value() F {
	return s.value
}

type DealerOutput[F algebra.PrimeFieldElement[F]] struct {
	shares ds.Map[sharing.ID, *Share[F]]
}

func (do *DealerOutput[F]) Shares() ds.Map[sharing.ID, *Share[F]] {
	return do.shares
}

type Scheme[F algebra.PrimeFieldElement[F]] struct {
	accessStructure *sharing.HierarchicalConjunctiveThresholdAccessStructure
	field           algebra.PrimeField[F]
}

func NewScheme[F algebra.PrimeFieldElement[F]](accessStructure *sharing.HierarchicalConjunctiveThresholdAccessStructure, field algebra.PrimeField[F]) (*Scheme[F], error) {
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

func (*Scheme[F]) Name() sharing.Name {
	return Name
}

func (s *Scheme[F]) Deal(secret *Secret[F], prng io.Reader) (*DealerOutput[F], error) {
	output, _, err := s.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not deal shares")
	}
	return output, nil
}

func (s *Scheme[F]) DealRandom(prng io.Reader) (*DealerOutput[F], *Secret[F], error) {
	output, secret, _, err := s.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not deal random shares")
	}
	return output, secret, nil
}

func (s *Scheme[F]) Reconstruct(shares ...*Share[F]) (secret *Secret[F], err error) {
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
	slices.Sort(quorum)
	if !s.AccessStructure().Shareholders().IsSuperSet(hashset.NewComparable(quorum...).Freeze()) ||
		!s.AccessStructure().IsQualified(quorum...) {

		return nil, sharing.ErrMembership.WithMessage("invalid quorum")
	}

	m, err := s.buildMatrix(quorum)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not build matrix")
	}
	d := m.Determinant()
	if d.IsZero() {
		return nil, sharing.ErrMembership.WithMessage("unqualified set")
	}

	shareValues := make([]F, len(quorum))
	for i, id := range quorum {
		shareValues[i] = sharesMap[id].value
	}
	m0, err := m.SetColumn(0, shareValues)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not set column")
	}
	d0 := m0.Determinant()

	secretValue, err := d0.TryDiv(d)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not divide determinants during reconstruction")
	}
	secret = &Secret[F]{
		value: secretValue,
	}
	return secret, nil
}

func (s *Scheme[F]) AccessStructure() *sharing.HierarchicalConjunctiveThresholdAccessStructure {
	return s.accessStructure
}

func (s *Scheme[F]) DealAndRevealDealerFunc(secret *Secret[F], prng io.Reader) (*DealerOutput[F], *polynomials.Polynomial[F], error) {
	if secret == nil || utils.IsNil(secret.value) {
		return nil, nil, sharing.ErrIsNil.WithMessage("secret is nil")
	}
	if prng == nil {
		return nil, nil, sharing.ErrIsNil.WithMessage("prng is nil")
	}

	degree := s.accessStructure.Levels()[len(s.AccessStructure().Levels())-1].Threshold() - 1
	polys, err := polynomials.NewPolynomialRing(s.field)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create polynomial ring")
	}
	dealerFunc, err := polys.RandomPolynomialWithConstantTerm(degree, secret.Value(), prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not sample dealer polynomial")
	}

	shares := hashmap.NewComparable[sharing.ID, *Share[F]]()
	d := 0
	for _, level := range s.AccessStructure().Levels() {
		p := dealerFunc.Clone()
		for range d {
			p = p.Derivative()
		}
		for id := range level.Shareholders().Iter() {
			shareValue := p.Eval(s.field.FromUint64(uint64(id)))
			shares.Put(id, &Share[F]{
				id:    id,
				value: shareValue,
			})
		}
		d = level.Threshold()
	}

	output := &DealerOutput[F]{
		shares: shares.Freeze(),
	}
	return output, dealerFunc, nil
}

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

// ShareToAdditiveShare converts this Shamir share to an additive share by multiplying
// by the appropriate Lagrange coefficient. The resulting additive shares can
// be summed to reconstruct the secret.
func (s *Scheme[F]) ShareToAdditiveShare(share *Share[F], quorum *sharing.UnanimityAccessStructure) (*additive.Share[F], error) {
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

func checkConstraints[F algebra.PrimeFieldElement[F]](ac *sharing.HierarchicalConjunctiveThresholdAccessStructure, field algebra.PrimeField[F]) error {
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

	q, _ := field.Order().Big().Float64()
	n := prevMax
	k := uint64(ac.Levels()[len(ac.Levels())-1].Threshold())

	// constraint 2 (equation 29): 2^(−k) · (k+1)^((k+1)/2) · N^((k−1)k/2) < q = |F|
	if math.Pow(2.0, -float64(k))*math.Pow(float64(k)+1.0, (float64(k)+1.0)/2.0)*math.Pow(float64(n), (float64(k)-1.0)*float64(k)/2.0) >= q {
		return sharing.ErrFailed.WithMessage("constraint failed")
	}

	// constraint 3 (equation 35): α(k)N^((k−1)(k−2)/2) < q = |F| where α(k) := 2^(−k+2) ·(k−1)^((k−1)/2) ·(k−1)!
	if k > 20 {
		// this will overflow factorial anyway
		return sharing.ErrFailed.WithMessage("too big threshold")
	}
	alpha := math.Pow(2.0, 2.0-float64(k)) * math.Pow(float64(k-1), (float64(k)-1.0)/2.0) * float64(factorial(k-1))
	if (alpha * math.Pow(float64(n), (float64(k)-1.0)*(float64(k)-2)/2.0)) >= q {
		return sharing.ErrFailed.WithMessage("constraint failed")
	}

	return nil
}

func factorial(n uint64) uint64 {
	f := uint64(1)
	for i := uint64(2); i <= n; i++ {
		f *= i
	}
	return f
}
