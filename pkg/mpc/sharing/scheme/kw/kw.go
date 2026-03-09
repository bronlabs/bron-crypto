package kw

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// Name is the canonical identifier for this secret sharing scheme.
const Name sharing.Name = "Karchmer-Wigderson MSP-based secret sharing scheme"

// DealerFunc is the full lambda column vector (M * r) produced during dealing.
// It is exposed so that protocols requiring the dealer's internal state (e.g.
// verifiable secret sharing) can access it.
type DealerFunc[FE algebra.PrimeFieldElement[FE]] = mat.Matrix[FE]

// DealerOutput contains the result of a dealing operation: a map from
// shareholder IDs to their corresponding shares.
type DealerOutput[FE algebra.PrimeFieldElement[FE]] struct {
	shares ds.Map[sharing.ID, *Share[FE]]
}

// Shares returns the map of shareholder IDs to shares.
func (d *DealerOutput[FE]) Shares() ds.Map[sharing.ID, *Share[FE]] {
	return d.shares
}
