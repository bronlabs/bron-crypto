# Batch Schnorr Zero-Knowledge proof of knowledge

This package implements the Batch Schnorr proof of knowledge of dlogs as described in [GLSY04] fig. 2.

Given the statements $x_i = g * w_i$, where $g$ is the base point it computes:

* commitment: $a = s * g$, where $s$ is randomly selected value,
* response: $z = s + \Sigma_i (w_i * e^i)$, where $e$ is the challenge.

Verification checks that: $g * z = a + \Sigma_i (x_i * e^i)$

[GLSY04]: <https://www.khoury.northeastern.edu/home/koods/papers/gennaro04batching.pdf>
