package feldman

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// DealerOutput contains the result of a Feldman VSS dealing operation:
// a map of shares and the verification vector for share verification.
type DealerOutput[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	shares ds.Map[sharing.ID, *Share[FE]]
	v      VerificationVector[E, FE]
}

// Shares returns the map of shareholder IDs to their corresponding shares.
func (d *DealerOutput[E, FE]) Shares() ds.Map[sharing.ID, *Share[FE]] {
	if d == nil {
		return nil
	}
	return d.shares
}

// VerificationMaterial returns the verification vector V = (g^{a_0}, g^{a_1}, ..., g^{a_{t-1}})
// which allows shareholders to verify their shares without revealing the secret.
func (d *DealerOutput[E, FE]) VerificationMaterial() VerificationVector[E, FE] {
	if d == nil {
		return nil
	}
	return d.v
}
