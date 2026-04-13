package feldman

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
)

// DealerOutput contains the result of a Feldman VSS dealing operation: a map
// from shareholder IDs to their shares, and the public verification vector
// V = [r]G.
type DealerOutput[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	shares ds.Map[sharing.ID, *kw.Share[FE]]
	v      *VerificationVector[E, FE]
}

// Shares returns the map of shareholder IDs to their corresponding shares.
func (d *DealerOutput[E, FE]) Shares() ds.Map[sharing.ID, *kw.Share[FE]] {
	return d.shares
}

// VerificationMaterial returns the public verification vector V = [r]G. This
// is the commitment that shareholders use to verify their shares without
// learning the secret or the random column r.
func (d *DealerOutput[E, FE]) VerificationMaterial() *VerificationVector[E, FE] {
	return d.v
}
