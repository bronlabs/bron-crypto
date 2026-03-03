package feldman

import (
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

type DealerOutput[
	S sharing.LinearShare[S, SV], SV any,
	LFTS sharing.Share[LFTS], LFTEREPR, AC any,
] struct {
	liftedDealerFunc sharing.DealerFunc[LFTS, LFTEREPR, AC]
	shares           ds.Map[sharing.ID, S]
}

func (d *DealerOutput[S, SV, LFTS, LFTEREPR, AC]) Shares() ds.Map[sharing.ID, S] {
	if d == nil {
		return nil
	}
	return d.shares
}

func (d *DealerOutput[S, SV, LFTS, LFTEREPR, AC]) VerificationMaterial() sharing.DealerFunc[LFTS, LFTEREPR, AC] {
	if d == nil {
		return nil
	}
	return d.liftedDealerFunc
}
