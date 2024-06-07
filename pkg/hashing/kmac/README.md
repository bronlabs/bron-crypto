# KMAC

This directory contains implementations of KMAC128 and KMAC256 as specified in [1] and relies on the [golang crypto package](https://pkg.go.dev/golang.org/x/crypto/sha3) for the cSHAKE primitives.

[1]: https://doi.org/10.6028/NIST.SP.800-185 (NIST Special Publication 800-185, "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash and ParallelHash")