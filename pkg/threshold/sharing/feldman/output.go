package feldman

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

type DealerOutput[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	shares ds.Map[sharing.ID, *Share[FE]]
	v      VerificationVector[E, FE]
}

func (d *DealerOutput[E, FE]) Shares() ds.Map[sharing.ID, *Share[FE]] {
	if d == nil {
		return nil
	}
	return d.shares
}

func (d *DealerOutput[E, FE]) VerificationMaterial() VerificationVector[E, FE] {
	if d == nil {
		return nil
	}
	return d.v
}
