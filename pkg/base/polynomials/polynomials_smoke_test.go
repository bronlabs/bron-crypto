package polynomials_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
)

func _[ME algebra.ModuleElement[ME, RE], RE algebra.RingElement[RE]]() {
	var (
		_ algebra.PolynomialRing[*polynomials.Polynomial[RE], RE] = (*polynomials.PolynomialRing[RE])(nil)
		_ algebra.Polynomial[*polynomials.Polynomial[RE], RE]     = (*polynomials.Polynomial[RE])(nil)

		_ algebra.PolynomialModule[
			*polynomials.ModuleValuedPolynomial[ME, RE],
			*polynomials.Polynomial[RE],
			ME,
			RE,
		] = (*polynomials.PolynomialModule[ME, RE])(nil)
		_ algebra.ModuleValuedPolynomial[
			*polynomials.ModuleValuedPolynomial[ME, RE],
			*polynomials.Polynomial[RE],
			ME,
			RE,
		] = (*polynomials.ModuleValuedPolynomial[ME, RE])(nil)

		_ algebra.Ring[*polynomials.DirectSumOfPolynomials[RE]]        = (*polynomials.DirectSumOfPolynomialRings[RE])(nil)
		_ algebra.RingElement[*polynomials.DirectSumOfPolynomials[RE]] = (*polynomials.DirectSumOfPolynomials[RE])(nil)

		_ algebra.Module[*polynomials.DirectSumOfModuleValuedPolynomials[ME, RE], RE]        = (*polynomials.DirectSumOfPolynomialModules[ME, RE])(nil)
		_ algebra.ModuleElement[*polynomials.DirectSumOfModuleValuedPolynomials[ME, RE], RE] = (*polynomials.DirectSumOfModuleValuedPolynomials[ME, RE])(nil)
	)
}
