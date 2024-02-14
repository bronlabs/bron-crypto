# Chaum Pedersen Zero-Knowledge proof dlog equality

This package implements the Chaum-Pedersen proof of dlog equality as in [GLOW20].
Given the statements $x1 = g1 * w$, $x2 = g2 * w$, where $g$ is the base point it computes:

* commitment: $a1 = s * g1$, $a2 = s * g2$, where $s$ is randomly selected value,
* response: $z = s + e * w$, where $e$ is the challenge.

Verification checks that: $g1 * z = a1 + x1 * e$ and $g2 * z = a2 + x2 * e$.

[GLOW20]: <https://eprint.iacr.org/2020/096.pdf>
