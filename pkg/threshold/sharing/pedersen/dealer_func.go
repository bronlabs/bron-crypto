package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
)

type DealerFunc[S algebra.PrimeFieldElement[S]] struct {
	G *polynomials.Polynomial[S]
	H *polynomials.Polynomial[S]
}

func NewDealerFunc[S algebra.PrimeFieldElement[S]](g *polynomials.Polynomial[S], h *polynomials.Polynomial[S]) *DealerFunc[S] {
	return &DealerFunc[S]{G: g, H: h}
}

type LiftedDealerFunc[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	G *polynomials.ModuleValuedPolynomial[G, S]
	H *polynomials.ModuleValuedPolynomial[G, S]
}

func (df *LiftedDealerFunc[G, S]) VerificationVector() VerificationVector[G, S] {
	return df.G.Op(df.H)
}

func liftDealerFuncToExp[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](dealerFunc *DealerFunc[S], baseG, baseH G) (*LiftedDealerFunc[G, S], error) {
	gg, err := polynomials.LiftPolynomial(dealerFunc.G, baseG)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot lift polynomial")
	}
	hh, err := polynomials.LiftPolynomial(dealerFunc.H, baseH)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot lift polynomial")
	}

	return &LiftedDealerFunc[G, S]{
		G: gg,
		H: hh,
	}, nil
}
