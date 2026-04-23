# polynomials

Univariate polynomial rings and modules over algebraic structures, together with
direct-power constructions for working with tuples of polynomials.

## Core types

| Structure | Element | Description |
|---|---|---|
| `PolynomialRing[S]` | `Polynomial[S]` | Ring R[x] of scalar-coefficient polynomials over a finite ring R |
| `PolynomialModule[ME, S]` | `ModuleValuedPolynomial[ME, S]` | Module M[x] of polynomials whose coefficients live in a finite module M |

## Direct-power types

| Structure | Element | Description |
|---|---|---|
| `DirectPowerOfPolynomialRings[S]` | `DirectPowerOfPolynomials[S]` | Direct power of scalar polynomial rings |
| `DirectPowerOfPolynomialModules[C, S]` | `DirectPowerOfModuleValuedPolynomials[C, S]` | Direct power of module-valued polynomial modules |

## Lifting

A scalar polynomial can be *lifted* into a module-valued polynomial by
multiplying each coefficient by a base module element:

- `LiftPolynomial` -- lifts a single polynomial.
- `LiftDirectPowerOfPolynomialsToExponent` -- lifts an entire direct power given
  per-component base points.

## Serialisation

Both `Polynomial` and `ModuleValuedPolynomial` support:

- `Bytes` / `FromBytes` -- raw fixed-size coefficient encoding.
- `MarshalCBOR` / `UnmarshalCBOR` -- CBOR serialisation.
