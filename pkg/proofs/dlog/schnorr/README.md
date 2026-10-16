# Schnorr Zero-Knowledge proof of knowledge

This package implements the regular Schnorr proof of knowledge of dlog.
Given the statement $x = g * w$, where $g$ is the base point it computes:

* commitment: $a = s * g$, where $s$ is randomly selected value,
* response: $z = s + e * w$, where $e$ is the challenge.

Verification checks that: $g * z = a + x * e$


## Reference

<!-- paper: docs/papers/schnorr91.pdf -->
<!-- paper: docs/papers/Maurer09.pdf -->
- [1] Maurer, U. [Unifying Zero-Knowledge Proofs of Knowledge](https://crypto-test.ethz.ch/publications/files/Maurer09.pdf). AFRICACRYPT 2009.

