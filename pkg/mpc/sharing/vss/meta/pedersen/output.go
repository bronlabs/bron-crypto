package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

type DealerOutput[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	shares ds.Map[sharing.ID, *Share[S]]
	v      *VerificationVector[E, S]
}

func (d *DealerOutput[E, S]) Shares() ds.Map[sharing.ID, *Share[S]] {
	return d.shares
}

func (d *DealerOutput[E, S]) VerificationVector() *VerificationVector[E, S] {
	return d.v
}
