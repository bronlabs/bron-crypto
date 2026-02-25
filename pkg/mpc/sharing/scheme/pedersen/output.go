package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// DealerOutput contains the result of a Pedersen VSS dealing operation:
// a map of shares (each with secret and blinding components) and the verification vector.
type DealerOutput[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	shares ds.Map[sharing.ID, *Share[S]]
	v      VerificationVector[E, S]
}

// Shares returns the map of shareholder IDs to their corresponding shares.
func (d *DealerOutput[E, S]) Shares() ds.Map[sharing.ID, *Share[S]] {
	if d == nil {
		return nil
	}
	return d.shares
}

// VerificationVector returns the verification vector V = (g^{a_0}·h^{b_0}, ..., g^{a_{t-1}}·h^{b_{t-1}})
// which allows shareholders to verify their shares without revealing the secret.
func (d *DealerOutput[E, S]) VerificationVector() VerificationVector[E, S] {
	if d == nil {
		return nil
	}
	return d.v
}
