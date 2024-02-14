# Schnorr Zero-Knowledge proof of knowledge

This package implements the regular Schnorr proof of knowledge of dlog.
Given the statement $x = g * w$, where $g$ is the base point it computes:

* commitment: $a = s * g$, where $s$ is randomly selected value,
* response: $z = s + e * w$, where $e$ is the challenge.

Verification checks that: $g * z = a + x * e$
