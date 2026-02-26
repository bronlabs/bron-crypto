# polynomials

Univariate polynomial rings and modules over algebraic structures, together with
direct-sum constructions for working with tuples of polynomials.

## Core types

| Structure | Element | Description |
|---|---|---|
| `PolynomialRing[S]` | `Polynomial[S]` | Ring R[x] of scalar-coefficient polynomials over a finite ring R |
| `PolynomialModule[ME, S]` | `ModuleValuedPolynomial[ME, S]` | Module M[x] of polynomials whose coefficients live in a finite module M |

## Direct-sum types

| Structure | Element | Description |
|---|---|---|
| `DirectSumOfPolynomialRings[S]` | `DirectSumOfPolynomials[S]` | Direct sum of scalar polynomial rings |
| `DirectSumOfPolynomialModules[C, S]` | `DirectSumOfModuleValuedPolynomials[C, S]` | Direct sum of module-valued polynomial modules |

## Lifting

A scalar polynomial can be *lifted* into a module-valued polynomial by
multiplying each coefficient by a base module element:

- `LiftPolynomial` -- lifts a single polynomial.
- `LiftDirectSumOfPolynomialsToExponent` -- lifts an entire direct sum given
  per-component base points.

## Serialisation

Both `Polynomial` and `ModuleValuedPolynomial` support:

- `Bytes` / `FromBytes` -- raw fixed-size coefficient encoding.
- `MarshalCBOR` / `UnmarshalCBOR` -- CBOR serialisation.
