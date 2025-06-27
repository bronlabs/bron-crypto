package shamir

import (
	"encoding/binary"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials/interpolation/lagrange"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
)

type (
	PrimeField[FE FieldElement[FE]]                = algebra.PrimeField[FE]
	FieldElement[FE algebra.PrimeFieldElement[FE]] = algebra.PrimeFieldElement[FE]
	DealerFunc[FE FieldElement[FE]]                = polynomials.Polynomial[FE]
)

const Name sharing.Name = "Shamir's Secret Sharing"

func NewScheme[FE FieldElement[FE]](f PrimeField[FE], threshold uint, shareholders ds.Set[sharing.ID]) (*Scheme[FE], error) {
	if f == nil {
		return nil, errs.NewIsNil("invalid field")
	}
	if shareholders == nil {
		return nil, errs.NewIsNil("shareholders is nil")
	}
	if threshold < 2 {
		return nil, errs.NewValue("threshold cannot be less than 2")
	}
	if threshold > uint(shareholders.Size()) {
		return nil, errs.NewValue("threshold cannot be greater than total number of shareholders")
	}
	ac, err := NewAccessStructure(threshold, shareholders)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create access structure")
	}
	ring, err := polynomials.NewPolynomialRing(f)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create polynomial ring")
	}

	return &Scheme[FE]{
		f:        f,
		polyRing: ring,
		ac:       ac,
	}, nil
}

func SharingIDToLagrangeNode[F PrimeField[FE], FE FieldElement[FE]](f F, id sharing.ID) FE {
	return f.FromUint64(uint64(id))
}

type Scheme[FE FieldElement[FE]] struct {
	f        PrimeField[FE]
	polyRing polynomials.PolynomialRing[FE]
	ac       *AccessStructure
}

func (d *Scheme[FE]) Name() sharing.Name {
	return Name
}

func (d *Scheme[FE]) SharingIDToLagrangeNode(id sharing.ID) FE {
	return SharingIDToLagrangeNode(d.f, id)
}

func (d *Scheme[FE]) AccessStructure() *AccessStructure {
	return d.ac
}

func (d *Scheme[FE]) PolynomialRing() polynomials.PolynomialRing[FE] {
	return d.polyRing
}

func (d *Scheme[FE]) DealRandomAndRevealDealerFunc(prng io.Reader) (*DealerOutput[FE], *Secret[FE], DealerFunc[FE], error) {
	if prng == nil {
		return nil, nil, nil, errs.NewIsNil("prng is nil")
	}
	value, err := d.f.Random(prng)
	if err != nil {
		return nil, nil, nil, errs.WrapRandomSample(err, "could not sample field element")
	}
	secret := NewSecret(value)
	shares, dealerFunc, err := d.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "could not create shares")
	}
	return shares, secret, dealerFunc, nil
}

func (d *Scheme[FE]) DealRandom(prng io.Reader) (*DealerOutput[FE], *Secret[FE], error) {
	shares, secret, _, err := d.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not deal random shares")
	}
	return shares, secret, nil
}

func (d *Scheme[FE]) DealAndRevealDealerFunc(secret *Secret[FE], prng io.Reader) (*DealerOutput[FE], DealerFunc[FE], error) {
	if secret == nil {
		return nil, nil, errs.NewIsNil("secret is nil")
	}
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng is nil")
	}
	poly, err := d.polyRing.RandomPolynomialWithConstantTerm(int(d.ac.t-1), secret.v, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not generate random polynomial")
	}
	shares := hashmap.NewComparable[sharing.ID, *Share[FE]]()
	for id := range d.ac.ps.Iter() {
		node := d.SharingIDToLagrangeNode(id)
		shares.Put(id, &Share[FE]{
			id: id,
			v:  poly.Eval(node),
		})
	}
	return &DealerOutput[FE]{shares: shares.Freeze()}, poly, nil
}

func (d *Scheme[FE]) Deal(secret *Secret[FE], prng io.Reader) (*DealerOutput[FE], error) {
	out, _, err := d.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not deal shares")
	}
	return out, nil
}

func (d *Scheme[FE]) Reconstruct(shares ...*Share[FE]) (*Secret[FE], error) {
	sharesSet := hashset.NewHashable[*Share[FE]](shares...)
	ids, err := sharing.CollectIDs(sharesSet.List()...)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not collect IDs from shares")
	}
	if !d.ac.IsAuthorized(ids...) {
		return nil, errs.NewFailed("shares are not authorized by the access structure")
	}
	nodes := make([]FE, sharesSet.Size())
	values := make([]FE, sharesSet.Size())
	for i, share := range sharesSet.Iter2() {
		nodes[i] = d.SharingIDToLagrangeNode(share.ID())
		values[i] = share.Value()
	}
	reconstructed, err := lagrange.InterpolateAt(d.f, nodes, values, d.f.Zero())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not interpolate polynomial")
	}
	return &Secret[FE]{reconstructed}, nil
}

func (d *Scheme[FE]) Field() PrimeField[FE] {
	return d.f
}

func LagrangeCoefficients[FE FieldElement[FE]](field PrimeField[FE], sharingIds ...sharing.ID) (ds.Map[sharing.ID, FE], error) {
	if hashset.NewComparable(sharingIds...).Size() != len(sharingIds) {
		return nil, errs.NewMembership("invalid sharing id hash set")
	}

	sharingIdsScalar := make([]FE, len(sharingIds))
	for i, id := range sharingIds {
		sharingIdsScalar[i] = SharingIDToLagrangeNode(field, id)
	}

	basisPolynomials, err := lagrange.BasisAt(field, sharingIdsScalar, field.Zero())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute all basis polynomials at x=0")
	}

	result := hashmap.NewComparable[sharing.ID, FE]()
	for i, li := range basisPolynomials {
		result.Put(sharingIds[i], li)
	}

	return result.Freeze(), nil
}

func NewAccessStructure(t uint, ps ds.Set[sharing.ID]) (*AccessStructure, error) {
	if ps == nil {
		return nil, errs.NewIsNil("party set is nil")
	}
	if t < 2 {
		return nil, errs.NewValue("threshold cannot be less than 2")
	}
	if t > uint(ps.Size()) {
		return nil, errs.NewValue("total cannot be less than threshold")
	}
	return &AccessStructure{
		t:  t,
		ps: ps,
	}, nil
}

type AccessStructure struct {
	t  uint
	ps ds.Set[sharing.ID]
}

func (a *AccessStructure) Threshold() uint {
	return a.t
}

func (a *AccessStructure) Shareholders() ds.Set[sharing.ID] {
	return a.ps
}

func (a *AccessStructure) IsAuthorized(ids ...sharing.ID) bool {
	idsSet := hashset.NewComparable(ids...)
	return idsSet.Size() >= int(a.t) &&
		idsSet.Size() <= int(a.ps.Size()) &&
		idsSet.Freeze().IsSubSet(a.ps)
}

func (a *AccessStructure) Equal(other *AccessStructure) bool {
	if a == nil || other == nil {
		return a == other
	}
	if a.t != other.t {
		return false
	}
	if a.ps.Size() != other.ps.Size() {
		return false
	}
	return a.ps.Equal(other.ps)
}

func (a *AccessStructure) Clone() *AccessStructure {
	if a == nil {
		return nil
	}
	return &AccessStructure{
		t:  a.t,
		ps: a.ps.Clone(),
	}
}

func NewShare[FE FieldElement[FE]](id sharing.ID, value FE, ac *AccessStructure) (*Share[FE], error) {
	if ac != nil && !ac.Shareholders().Contains(id) {
		return nil, errs.NewMembership("share ID %d is not a valid shareholder", id)
	}
	return &Share[FE]{
		id: id,
		v:  value,
	}, nil
}

type Share[FE FieldElement[FE]] struct {
	id sharing.ID
	v  FE
}

func (s *Share[FE]) ToAdditive(qualifiedSet sharing.MinimalQualifiedAccessStructure) (*additive.Share[FE], error) {
	field, ok := s.v.Structure().(PrimeField[FE])
	if !ok {
		return nil, errs.NewType("share value does not implement Field interface")
	}
	lambdas, err := LagrangeCoefficients(field, qualifiedSet.Shareholders().List()...)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute Lagrange coefficients")
	}
	lambda_i, exists := lambdas.Get(s.id)
	if !exists {
		return nil, errs.NewMembership("share ID %d is not a valid shareholder", s.id)
	}
	converted := lambda_i.Mul(s.v)
	return additive.NewShare(s.id, converted, &qualifiedSet)
}

func (s *Share[_]) ID() sharing.ID {
	return s.id
}

func (s *Share[FE]) Value() FE {
	return s.v
}

func (s *Share[FE]) Equal(other *Share[FE]) bool {
	if s == nil || other == nil {
		return s == other
	}
	return s.id == other.id && s.v.Equal(other.v)
}

func (s *Share[FE]) Op(other *Share[FE]) *Share[FE] {
	return s.Add(other)
}

func (s *Share[FE]) Add(other *Share[FE]) *Share[FE] {
	return &Share[FE]{
		id: s.id,
		v:  s.v.Add(other.v),
	}
}

func (s *Share[FE]) ScalarOp(scalar FE) *Share[FE] {
	return s.ScalarMul(scalar)
}

func (s *Share[FE]) ScalarMul(scalar FE) *Share[FE] {
	return &Share[FE]{
		id: s.id,
		v:  s.v.Mul(scalar),
	}
}

func (s *Share[FE]) Clone() *Share[FE] {
	return &Share[FE]{
		id: s.id,
		v:  s.v.Clone(),
	}
}

func (s *Share[FE]) HashCode() base.HashCode {
	return base.HashCode(s.id) ^ s.v.HashCode()
}

func (s *Share[FE]) Bytes() []byte {
	buf := s.Value().Bytes()
	binary.BigEndian.AppendUint64(buf, uint64(s.ID()))
	return buf
}

func NewSecret[FE FieldElement[FE]](value FE) *Secret[FE] {
	return &Secret[FE]{v: value}
}

type Secret[FE FieldElement[FE]] struct {
	v FE
}

func (s *Secret[FE]) Value() FE {
	return s.v
}

func (s *Secret[FE]) Equal(other *Secret[FE]) bool {
	if s == nil || other == nil {
		return s == other
	}
	return s.v.Equal(other.v)
}

func (s *Secret[FE]) Clone() *Secret[FE] {
	return &Secret[FE]{
		v: s.v.Clone(),
	}
}

type DealerOutput[FE FieldElement[FE]] struct {
	shares ds.Map[sharing.ID, *Share[FE]]
}

func (d *DealerOutput[FE]) Shares() ds.Map[sharing.ID, *Share[FE]] {
	return d.shares
}

func _[F PrimeField[FE], FE FieldElement[FE]]() {
	var (
		_ sharing.DealerOutput[*Share[FE]]                                               = (*DealerOutput[FE])(nil)
		_ sharing.LinearShare[*Share[FE], FE, *additive.Share[FE], FE, *AccessStructure] = (*Share[FE])(nil)
		_ sharing.LinearlyShareableSecret[*Secret[FE], FE]                               = (*Secret[FE])(nil)

		_ sharing.ThresholdSSS[*Share[FE], *Secret[FE], *DealerOutput[FE], *AccessStructure]
		_ sharing.PolynomialLSSS[*Share[FE], FE, *additive.Share[FE], *Secret[FE], FE, *DealerOutput[FE], *AccessStructure] = (*Scheme[FE])(nil)
	)
}
