package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

type DealerOutput[
	US sharing.Share[US],
	USV algebra.PrimeFieldElement[USV],
	LFTUDF any,
] struct {
	shares             ds.Map[sharing.ID, *Share[US, USV]]
	verificationVector LFTUDF
}

func (d *DealerOutput[US, USV, LFTUDF]) Shares() ds.Map[sharing.ID, *Share[US, USV]] {
	return d.shares
}

func (d *DealerOutput[US, USV, LFTUDF]) VerificationVector() LFTUDF {
	return d.verificationVector
}
