package feldman

import (
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

type DealerOutput[S sharing.Share[S], LFTDF any] struct {
	liftedDealerFunc LFTDF
	shares           ds.Map[sharing.ID, S]
}

func (d *DealerOutput[S, LFTDF]) Shares() ds.Map[sharing.ID, S] {
	if d == nil {
		return nil
	}
	return d.shares
}

func (d *DealerOutput[S, LFTDF]) VerificationMaterial() LFTDF {
	if d == nil {
		return *new(LFTDF)
	}
	return d.liftedDealerFunc
}
