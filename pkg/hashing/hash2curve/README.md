# `hash2curve`

This package follows the [RFC 9380](https://datatracker.ietf.org/doc/html/rfc9380) to implement
unbiased hash-to-curve functions, used encoding or hashing an arbitrary string to a point and/or a scalar on an elliptic curve.

## Hash-to-curve functions
The following functions are exported in this package:
1. `hash_to_scalar(msg, count) -> (u_0, ..., u_(count - 1))`, a stylistic alias for `hash_to_field` (see below).
2. [`hash_to_curve(msg) -> (P)`](https://datatracker.ietf.org/doc/html/rfc9380#name-encoding-byte-strings-to-el) is a uniform encoding from byte strings to points in the prime-order subgroup of the EC. That is, the distribution of its output is statistically close to uniform. It's specification is is as follows:
```golang
1. u = hash_to_field(msg, 2)
2. Q0 = map_to_curve(u[0])
3. Q1 = map_to_curve(u[1])
4. R = Q0 + Q1              // Point addition
5. P = clear_cofactor(R)    // Only if the curve has a cofactor > 1
6. return P
```

## Basic functions
The constructions in this section rely on three basic functions from RFC-9380:
- [`hash_to_field(msg, count) -> (u_0, ..., u_(count - 1))`](https://datatracker.ietf.org/doc/html/rfc9380#hashtofield) hashes arbitrary-length byte strings to a list of one or more elements of a finite field F.
- [`map_to_curve(u) -> Q`](https://datatracker.ietf.org/doc/html/rfc9380#mappings) calculates a point on the elliptic curve from an element of the finite field over which the curve is defined. 
- [`clear_cofactor(Q) -> P`](https://datatracker.ietf.org/doc/html/rfc9380#cofactor-clearing) sends any point on the curve to its prime-order subgroup.
