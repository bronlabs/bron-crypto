package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
)

type DealerOutput[
	US sharing.LinearShare[US, USV],
	USV algebra.PrimeFieldElement[USV],
	LFTUDF interface {
		algebra.Operand[LFTUDF]
		sharing.DealerFunc[LFTUS, LFTUSV, AC]
	}, LFTUS sharing.LinearShare[LFTUS, LFTUSV],
	LFTUSV algebra.PrimeGroupElement[LFTUSV, USV],
	AC accessstructures.Monotone,
] struct {
	shares             ds.Map[sharing.ID, *Share[US, USV]]
	verificationVector LFTUDF
}

func (d *DealerOutput[US, USV, LFTUDF, LFTUS, LFTUSV, AC]) Shares() ds.Map[sharing.ID, *Share[US, USV]] {
	return d.shares
}

func (d *DealerOutput[US, USV, LFTUDF, LFTUS, LFTUSV, AC]) VerificationVector() LFTUDF {
	return d.verificationVector
}
