package shamir

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials/interpolation/lagrange"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

// Scheme implements Shamir's (t,n) threshold secret sharing over a prime field.
type Scheme[FE algebra.PrimeFieldElement[FE]] struct {
	f        algebra.PrimeField[FE]
	polyRing *polynomials.PolynomialRing[FE]
	ac       *sharing.ThresholdAccessStructure
}

// NewScheme creates a new Shamir secret sharing scheme.
//
// Parameters:
//   - f: The prime field over which sharing is performed
//   - threshold: Minimum number of shares required for reconstruction (must be ≥ 2)
//   - shareholders: Set of shareholder IDs who will receive shares
//
// The threshold must not exceed the number of shareholders.
func NewScheme[FE algebra.PrimeFieldElement[FE]](f algebra.PrimeField[FE], threshold uint, shareholders ds.Set[sharing.ID]) (*Scheme[FE], error) {
	if f == nil {
		return nil, ErrIsNil.WithMessage("invalid field")
	}
	if shareholders == nil {
		return nil, ErrIsNil.WithMessage("shareholders is nil")
	}
	if threshold < 2 {
		return nil, ErrValue.WithMessage("threshold cannot be less than 2")
	}
	if threshold > uint(shareholders.Size()) {
		return nil, ErrValue.WithMessage("threshold cannot be greater than total number of shareholders")
	}
	ac, err := sharing.NewThresholdAccessStructure(threshold, shareholders)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("could not create access structure")
	}
	ring, err := polynomials.NewPolynomialRing(f)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("could not create polynomial ring")
	}

	return &Scheme[FE]{
		f:        f,
		polyRing: ring,
		ac:       ac,
	}, nil
}

// Name returns the canonical name of this scheme.
func (*Scheme[FE]) Name() sharing.Name {
	return Name
}

// SharingIDToLagrangeNode converts a shareholder ID to its field element representation.
func (d *Scheme[FE]) SharingIDToLagrangeNode(id sharing.ID) FE {
	return SharingIDToLagrangeNode(d.f, id)
}

// AccessStructure returns the threshold access structure for this scheme.
func (d *Scheme[FE]) AccessStructure() *sharing.ThresholdAccessStructure {
	return d.ac
}

// PolynomialRing returns the polynomial ring used for share generation.
func (d *Scheme[FE]) PolynomialRing() *polynomials.PolynomialRing[FE] {
	return d.polyRing
}

// DealRandomAndRevealDealerFunc generates shares for a random secret and returns
// the dealing polynomial. This is useful for protocols that need the polynomial
// for verification or further computation.
func (d *Scheme[FE]) DealRandomAndRevealDealerFunc(prng io.Reader) (*DealerOutput[FE], *Secret[FE], DealerFunc[FE], error) {
	if prng == nil {
		return nil, nil, nil, ErrIsNil.WithMessage("prng is nil")
	}
	value, err := d.f.Random(prng)
	if err != nil {
		return nil, nil, nil, errs2.Wrap(err).WithMessage("could not sample field element")
	}
	secret := NewSecret(value)
	shares, dealerFunc, err := d.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, nil, nil, errs2.Wrap(err).WithMessage("could not create shares")
	}
	return shares, secret, dealerFunc, nil
}

// DealRandom generates shares for a randomly sampled secret.
func (d *Scheme[FE]) DealRandom(prng io.Reader) (*DealerOutput[FE], *Secret[FE], error) {
	shares, secret, _, err := d.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("could not deal random shares")
	}
	return shares, secret, nil
}

// DealAndRevealDealerFunc creates shares for the given secret and returns the
// dealing polynomial f(x) where f(0) = secret.
func (d *Scheme[FE]) DealAndRevealDealerFunc(secret *Secret[FE], prng io.Reader) (*DealerOutput[FE], DealerFunc[FE], error) {
	if secret == nil {
		return nil, nil, ErrIsNil.WithMessage("secret is nil")
	}
	if prng == nil {
		return nil, nil, ErrIsNil.WithMessage("prng is nil")
	}
	poly, err := d.polyRing.RandomPolynomialWithConstantTerm(int(d.ac.Threshold()-1), secret.v, prng)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("could not generate random polynomial")
	}
	shares := hashmap.NewComparable[sharing.ID, *Share[FE]]()
	for id := range d.ac.Shareholders().Iter() {
		node := d.SharingIDToLagrangeNode(id)
		shares.Put(id, &Share[FE]{
			id: id,
			v:  poly.Eval(node),
		})
	}
	return &DealerOutput[FE]{shares: shares.Freeze()}, poly, nil
}

// Deal creates shares for the given secret.
func (d *Scheme[FE]) Deal(secret *Secret[FE], prng io.Reader) (*DealerOutput[FE], error) {
	out, _, err := d.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("could not deal shares")
	}
	return out, nil
}

// Reconstruct recovers the secret from a set of shares using Lagrange interpolation.
// At least threshold shares must be provided, and all shares must belong to authorized
// shareholders in the access structure.
func (d *Scheme[FE]) Reconstruct(shares ...*Share[FE]) (*Secret[FE], error) {
	sharesSet := hashset.NewHashable(shares...)
	ids, err := sharing.CollectIDs(sharesSet.List()...)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("could not collect IDs from shares")
	}
	if !d.ac.IsAuthorized(ids...) {
		return nil, ErrFailed.WithMessage("shares are not authorized by the access structure")
	}
	nodes := make([]FE, sharesSet.Size())
	values := make([]FE, sharesSet.Size())
	for i, share := range sharesSet.Iter2() {
		nodes[i] = d.SharingIDToLagrangeNode(share.ID())
		values[i] = share.Value()
	}
	reconstructed, err := lagrange.InterpolateAt(nodes, values, d.f.Zero())
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("could not interpolate polynomial")
	}
	return &Secret[FE]{reconstructed}, nil
}

// Field returns the prime field over which this scheme operates.
func (d *Scheme[FE]) Field() algebra.PrimeField[FE] {
	return d.f
}
