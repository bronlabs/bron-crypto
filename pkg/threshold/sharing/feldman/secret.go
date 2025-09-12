package feldman

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
)

func NewSecret[FE algebra.PrimeFieldElement[FE]](value FE) *Secret[FE] {
	return shamir.NewSecret(value)
}

type Secret[FE algebra.PrimeFieldElement[FE]] = shamir.Secret[FE]
