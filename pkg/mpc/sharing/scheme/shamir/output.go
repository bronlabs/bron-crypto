package shamir

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// DealerOutput contains the result of a dealing operation: a map from
// shareholder IDs to their corresponding shares.
type DealerOutput[FE algebra.PrimeFieldElement[FE]] struct {
	shares ds.Map[sharing.ID, *Share[FE]]
}

// Shares returns the map of shareholder IDs to shares.
func (d *DealerOutput[FE]) Shares() ds.Map[sharing.ID, *Share[FE]] {
	return d.shares
}
