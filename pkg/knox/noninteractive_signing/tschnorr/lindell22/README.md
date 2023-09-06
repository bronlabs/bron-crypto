# Lindell 2022 Schnorr non-interactive signing
This is essentially [interactive signing](../../../../signatures/threshold/tschnorr/lindell22/signing/interactive/README.md) from [Simple Three-Round Multiparty Schnorr Signing with Full Simulatability][Lin22] split into PreGen and Sign phase.
The PreGen consists of Round 1-3, where at last round each party stores $\left(k_i, R_0, R_1, ..., R_{n-1}\right)$ as the pre-signature
and the Non-Interactive Sign consist of Round 4 which requires pre-signature and the message to produce partial Schnorr signature.

[Lin22]: <https://eprint.iacr.org/2022/374.pdf>
