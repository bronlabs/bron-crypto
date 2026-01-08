package feldman

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
)

// NewSecret creates a new secret from a field element.
func NewSecret[FE algebra.PrimeFieldElement[FE]](value FE) *Secret[FE] {
	return shamir.NewSecret(value)
}

// Secret is a Feldman VSS secret, which is identical to a Shamir secret.
// This is the value s = f(0) that is shared among the shareholders.
type Secret[FE algebra.PrimeFieldElement[FE]] = shamir.Secret[FE]
