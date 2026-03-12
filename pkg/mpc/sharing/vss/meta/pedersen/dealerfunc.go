package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
)

type DealerFunc[FE algebra.PrimeFieldElement[FE]] struct {
	g *kw.DealerFunc[FE]
	h *kw.DealerFunc[FE]
}

type LiftedDealerFunc[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	g *mat.ModuleValuedMatrix[E, FE]
	h *mat.ModuleValuedMatrix[E, FE]
}
