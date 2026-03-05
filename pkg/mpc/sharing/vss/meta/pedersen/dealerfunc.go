package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
)

// DealerFunc wraps two underlying dealer functions: one for the secret
// shares and one for the blinding shares. This is returned by
// DealAndRevealDealerFunc to allow the caller to access the dealing components.
type DealerFunc[ULDF sharing.DealerFunc[US, USV, AC], US sharing.LinearShare[US, USV], USV algebra.PrimeFieldElement[USV], AC accessstructures.Monotone] struct {
	shares   ULDF
	blinding ULDF
}

func (f *DealerFunc[ULDF, US, USV, AC]) Shares() ULDF {
	return f.shares
}

func (f *DealerFunc[ULDF, US, USV, AC]) Blinding() ULDF {
	return f.blinding
}
