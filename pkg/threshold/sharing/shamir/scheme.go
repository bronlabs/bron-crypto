package shamir

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials/interpolation"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

type Scheme[FE algebra.PrimeFieldElement[FE]] struct {
	f        algebra.PrimeField[FE]
	polyRing *polynomials.PolynomialRing[FE]
	ac       *AccessStructure
}

func NewScheme[FE algebra.PrimeFieldElement[FE]](f algebra.PrimeField[FE], threshold uint, shareholders ds.Set[sharing.ID]) (*Scheme[FE], error) {
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

func (d *Scheme[FE]) Name() sharing.Name {
	return Name
}

func (d *Scheme[FE]) SharingIDToLagrangeNode(id sharing.ID) FE {
	return SharingIDToLagrangeNode(d.f, id)
}

func (d *Scheme[FE]) AccessStructure() *AccessStructure {
	return d.ac
}

func (d *Scheme[FE]) PolynomialRing() *polynomials.PolynomialRing[FE] {
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
	poly, err := d.polyRing.NewRandomWithConstantTerm(int(d.ac.t-1), secret.v, prng)
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
	sharesSet := hashset.NewHashable(shares...)
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
	reconstructed, err := interpolation.InterpolateAt(nodes, values, d.f.Zero())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not interpolate polynomial")
	}
	return &Secret[FE]{reconstructed}, nil
}

func (d *Scheme[FE]) Field() algebra.PrimeField[FE] {
	return d.f
}
