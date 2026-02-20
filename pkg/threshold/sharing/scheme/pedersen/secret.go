package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/scheme/shamir"
)

// Secret is a Pedersen VSS secret, which is identical to a Shamir secret.
// This is the value s = f(0) that is shared among the shareholders.
type Secret[S algebra.PrimeFieldElement[S]] = shamir.Secret[S]

// NewSecret creates a new secret from a field element.
func NewSecret[S algebra.PrimeFieldElement[S]](value S) *Secret[S] {
	return shamir.NewSecret(value)
}
