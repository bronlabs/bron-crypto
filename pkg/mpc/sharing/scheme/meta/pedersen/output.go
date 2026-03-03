package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
)

type DealerOutput[
	LFTUDF sharing.DealerFunc[LFTUDF, LFTS, LFTSV, AC],
	LFTSV algebra.PrimeGroupElement[LFTSV, SV],
	LFTS sharing.LinearShare[LFTS, LFTSV],
	SV algebra.PrimeFieldElement[SV],
	AC accessstructures.Monotone,
] struct {
	shares             ds.Map[sharing.ID, *Share[SV]]
	verificationVector LFTUDF
}

func (d *DealerOutput[LFTUDF, LFTSV, LFTS, SV, AC]) Shares() ds.Map[sharing.ID, *Share[SV]] {
	return d.shares
}

func (d *DealerOutput[LFTUDF, LFTSV, LFTS, SV, AC]) VerificationVector() LFTUDF {
	return d.verificationVector
}
