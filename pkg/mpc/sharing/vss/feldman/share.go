package feldman

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/shamir"
	"github.com/bronlabs/errs-go/errs"
)

// Share is a Feldman VSS share, which is identical to a Shamir share.
// The share value is f(i) where f is the dealing polynomial and i is the shareholder ID.
type Share[FE algebra.PrimeFieldElement[FE]] = shamir.Share[FE]

// NewShare creates a new Feldman share with the given ID and value.
// If an access structure is provided, validates that the ID is a valid shareholder.
func NewShare[FE algebra.PrimeFieldElement[FE]](id sharing.ID, v FE, ac *accessstructures.Threshold) (*Share[FE], error) {
	s, err := shamir.NewShare(id, v, ac)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create Feldman share")
	}
	return s, nil
}
