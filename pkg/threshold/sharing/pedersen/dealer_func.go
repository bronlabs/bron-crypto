package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
)

// DealerFunc represents the pair of polynomials (f, r) used for Pedersen VSS.
// f(x) is the secret polynomial with f(0) = s, and r(x) is the blinding polynomial.
type DealerFunc[S algebra.PrimeFieldElement[S]] struct {
	G *polynomials.Polynomial[S]
	H *polynomials.Polynomial[S]
}

// NewDealerFunc creates a new dealer function from the secret and blinding polynomials.
func NewDealerFunc[S algebra.PrimeFieldElement[S]](g *polynomials.Polynomial[S], h *polynomials.Polynomial[S]) *DealerFunc[S] {
	return &DealerFunc[S]{G: g, H: h}
}

// LiftedDealerFunc represents the dealer polynomials lifted to the exponent:
// (g^{f(x)}, h^{r(x)}). Used internally to compute the verification vector.
type LiftedDealerFunc[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	G *polynomials.ModuleValuedPolynomial[G, S]
	H *polynomials.ModuleValuedPolynomial[G, S]
}

// VerificationVector computes the verification vector by multiplying the lifted
// polynomials coefficient-wise: V_j = g^{a_j}·h^{b_j}.
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
