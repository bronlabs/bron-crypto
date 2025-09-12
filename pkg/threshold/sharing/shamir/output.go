package shamir

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

type DealerOutput[FE algebra.PrimeFieldElement[FE]] struct {
	shares ds.Map[sharing.ID, *Share[FE]]
}

func (d *DealerOutput[FE]) Shares() ds.Map[sharing.ID, *Share[FE]] {
	return d.shares
}
