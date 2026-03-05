package feldman

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
)

type DealerOutput[
	S sharing.LinearShare[S, SV], SV algebra.RingElement[SV],
	LFTDF interface {
		algebra.Operand[LFTDF]
		sharing.DealerFunc[LFTS, LFTSV, AC]
	}, LFTS sharing.LinearShare[LFTS, LFTSV],
	LFTSV algebra.ModuleElement[LFTSV, SV],
	AC accessstructures.Monotone,
] struct {
	verificationVector LFTDF
	shares             ds.Map[sharing.ID, S]
}

func (d *DealerOutput[S, SV, LFTDF, LFTS, LFTSV, AC]) Shares() ds.Map[sharing.ID, S] {
	if d == nil {
		return nil
	}
	return d.shares
}

func (d *DealerOutput[S, SV, LFTDF, LFTS, LFTSV, AC]) VerificationMaterial() LFTDF {
	if d == nil {
		return *new(LFTDF)
	}
	return d.verificationVector
}
