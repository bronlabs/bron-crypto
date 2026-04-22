// Package polynomials provides univariate polynomial rings and modules over
// algebraic structures, together with direct-power (Cartesian product)
// constructions for working with tuples of polynomials.
//
// The two core structures are:
//
//   - [PolynomialRing] — the ring R[x] of scalar-coefficient polynomials over
//     a finite ring R. Elements are [Polynomial] values.
//   - [PolynomialModule] — the module M[x] of module-valued polynomials whose
//     coefficients live in a finite module M and whose scalars come from the
//     scalar ring of M. Elements are [ModuleValuedPolynomial] values.
//
// A scalar polynomial can be "lifted" into a module-valued polynomial by
// multiplying each coefficient by a base module element (see [LiftPolynomial]).
//
// For protocols that operate on vectors of polynomials, the package also
// provides direct-power types:
//
//   - [DirectPowerOfPolynomialRings] / [DirectPowerOfPolynomials] — a direct power
//     of scalar polynomial rings, viewed as a module over the scalar ring.
//   - [DirectPowerOfPolynomialModules] / [DirectPowerOfModuleValuedPolynomials] —
//     a direct power of module-valued polynomial modules.
//
// [LiftDirectPowerOfPolynomialsToExponent] lifts an entire direct power of scalar
// polynomials into a direct power of module-valued polynomials given per-component
// base points.
package polynomials
