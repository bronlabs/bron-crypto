// Package shamir implements Shamir's (t,n) threshold secret sharing scheme.
//
// In Shamir's scheme, a secret s is encoded as the constant term of a random
// polynomial f(x) of degree t-1. Each share is a point (i, f(i)) on the polynomial.
// Any t shares can reconstruct s via Lagrange interpolation, while t-1 or fewer
// shares reveal no information about s (information-theoretic security).
package shamir

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials/interpolation"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

// DealerFunc is the polynomial used by the dealer to generate shares.
// The secret is f(0) and each share i is f(i).
type (
	DealerFunc[FE algebra.PrimeFieldElement[FE]] = *polynomials.Polynomial[FE]
)

// Name is the canonical name of this secret sharing scheme.
const Name sharing.Name = "Shamir's Secret Sharing"

// SharingIDToLagrangeNode converts a shareholder ID to the corresponding
// evaluation point on the polynomial (the x-coordinate for interpolation).
func SharingIDToLagrangeNode[FE algebra.PrimeFieldElement[FE]](f algebra.PrimeField[FE], id sharing.ID) FE {
	return f.FromUint64(uint64(id))
}

// LagrangeCoefficients computes the Lagrange basis polynomial values at x=0
// for the given set of shareholder IDs. These coefficients are used to
// convert Shamir shares to additive shares or to perform reconstruction.
//
// For shareholder i in set S, the coefficient λ_i = ∏_{j∈S,j≠i} j/(j-i).
func LagrangeCoefficients[FE algebra.PrimeFieldElement[FE]](field algebra.PrimeField[FE], sharingIds ...sharing.ID) (ds.Map[sharing.ID, FE], error) {
	if hashset.NewComparable(sharingIds...).Size() != len(sharingIds) {
		return nil, ErrMembership.WithMessage("invalid sharing id hash set")
	}

	sharingIdsScalar := make([]FE, len(sharingIds))
	for i, id := range sharingIds {
		sharingIdsScalar[i] = SharingIDToLagrangeNode(field, id)
	}

	basisPolynomials, err := interpolation.BasisAt(sharingIdsScalar, field.Zero())
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("could not compute all basis polynomials at x=0")
	}

	result := hashmap.NewComparable[sharing.ID, FE]()
	for i, li := range basisPolynomials {
		result.Put(sharingIds[i], li)
	}

	return result.Freeze(), nil
}
