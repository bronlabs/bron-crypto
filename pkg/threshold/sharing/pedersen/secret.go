package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
)

type Secret[S algebra.PrimeFieldElement[S]] = shamir.Secret[S]

func NewSecret[S algebra.PrimeFieldElement[S]](value S) *Secret[S] {
	return shamir.NewSecret(value)
}
