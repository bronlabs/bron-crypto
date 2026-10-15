# lindell17/signing

This package implements Lindell17 ECDSA signing rounds for an authorized
two-shareholder MSP quorum. DKG retains the original MSP shares and proves a
bounded Paillier encryption of every raw share component. Alternatively, the
trusted-dealer path supplies unproved ciphertexts whose correctness relies on
dealer honesty. At signing time both cosigners convert their local share for the
selected unanimity quorum and refresh the resulting additive sharing with PRZS.

The MSP-to-additive conversion and PRZS refresh are repository adaptations of
the protocol in the paper. A signing session must contain exactly two
authorized shareholders. Constructors accept only the Fischlin and Randomised
Fischlin non-interactive compilers because signing requires straight-line
extraction; Fiat-Shamir is rejected. Both parties must select the same compiler.
The caller-provided `io.Reader` must be a cryptographically secure random
source.

The secondary applies the primary's reconstruction coefficients under
Paillier encryption. Each exponent is reduced as
`k2^-1 * r * coefficient mod q` before it is applied to the corresponding
ciphertext; the encrypted components are never first aggregated and then
scaled. The complementary primary PRZS term and refreshed secondary share are
also reduced before fresh encryption.

For honestly generated DKG ciphertexts, each combined representative is less
than `3*q`; this yields the bound enforced by `CalcC3`:

`2 * (q^3 + 3*d*q^2 + 2*q) < N`.

The underlying range proof's malicious-prover soundness guarantees only a
representative below `4*q`. Deployments that rely on this malicious bound must
also ensure the stronger conservative condition

`2 * (q^3 + 4*d*q^2 + 2*q) < N`,

where `d` is the number of encrypted primary MSP components and `N` is the
Paillier modulus. `CalcC3` does not currently enforce this stronger condition.
Production setup requires at least 3072-bit Paillier moduli, which provides a
large margin for the supported curves and practical MSP component counts, but
callers must still account for their actual `d`.
