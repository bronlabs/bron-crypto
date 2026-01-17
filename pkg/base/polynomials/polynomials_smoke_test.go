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
	)
}
