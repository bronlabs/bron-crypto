package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// DealerOutput contains the result of a Pedersen VSS dealing operation: a map
// from shareholder IDs to their Pedersen shares (each carrying both secret and
// blinding components), and the public verification vector V = [r_g]G + [r_h]H.
type DealerOutput[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	shares ds.Map[sharing.ID, *Share[S]]
	v      *VerificationVector[E, S]
}

// Shares returns the map of shareholder IDs to their corresponding Pedersen shares.
func (d *DealerOutput[E, S]) Shares() ds.Map[sharing.ID, *Share[S]] {
	return d.shares
}

// VerificationMaterial returns the public verification vector
// V = [r_g]G + [r_h]H. This is the perfectly hiding commitment that
// shareholders use to verify their shares. Unlike Feldman's verification
// vector, V does not reveal the secret in the exponent.
func (d *DealerOutput[E, S]) VerificationMaterial() *VerificationVector[E, S] {
	return d.v
}
