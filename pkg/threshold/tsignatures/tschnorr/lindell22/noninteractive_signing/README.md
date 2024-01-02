# Lindell 2022 Schnorr non-interactive signing
This is essentially [interactive signing](../../../../signatures/threshold/tschnorr/lindell22/signing/interactive/README.md) from [Simple Three-Round Multiparty Schnorr Signing with Full Simulatability][Lin22]
split into PreGen and Sign phase with pre-signature re-randomization as described in 2.5 of [The many faces of Schnorr][Shoup23]
The PreGen consists of Round 1-3, where at last round each party stores
$\left(k_i, k2_i, R_0, R_1, ..., R_{n-1}, R2_0, R2_1, ..., R2_{n-1}, \delta_{i, 0}, \delta_{i, 1}, ..., \delta_{i, j - 1}, \delta_{0, i}, \delta_{1, i}, ..., \delta_{j - 1, i}\right)$
as the pre-signature
and the Non-Interactive Sign consist of Round 4 which requires pre-signature and the message to produce partial Schnorr signature.

## Re-randomizing pre-signatures via hashing
We use a hash function (hash to scalar) to derive the re-randomization tweak ($\delta$)
and use a second random group element ($R2$) as a part of the pre-signature.
To sign a message the effective pre-signature (used in the actual signature) is $R' = R + \delta R2$, where
$\delta = Hash2Scalar(publicKey, R, R2, presignatureIndex, message)$.
That way the effective pre-signature is not known before the message itself.

[Lin22]: <https://eprint.iacr.org/2022/374.pdf>
[Shoup23]: <https://eprint.iacr.org/2023/1019.pdf>
