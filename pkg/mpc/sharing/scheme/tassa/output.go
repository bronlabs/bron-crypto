package tassa

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// DealerOutput contains shares produced by one dealing execution.
type DealerOutput[F algebra.PrimeFieldElement[F]] struct {
	shares ds.Map[sharing.ID, *Share[F]]
}

// Shares returns the dealt shares indexed by shareholder ID.
func (do *DealerOutput[F]) Shares() ds.Map[sharing.ID, *Share[F]] {
	return do.shares
}
