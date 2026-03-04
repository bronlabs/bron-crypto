package isn

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// DealerOutput contains the shares produced by a dealing operation.
// It provides access to the mapping from shareholder IDs to their shares.
type DealerOutput[E algebra.GroupElement[E]] struct {
	shares ds.Map[sharing.ID, *Share[E]]
}

// Shares returns the map of shareholder IDs to their corresponding shares.
func (d *DealerOutput[E]) Shares() ds.Map[sharing.ID, *Share[E]] {
	return d.shares
}
