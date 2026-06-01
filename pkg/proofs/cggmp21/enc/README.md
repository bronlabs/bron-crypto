# Paillier Encryption in Range

This package implements the "Paillier Encryption in Range ZK" sigma protocol from Figure 11 of [CGGMP21](https://eprint.iacr.org/2021/060.pdf).

The prover API checks that the supplied Paillier plaintext opening has a signed
integer representative in the configured narrow range. The sigma protocol
itself proves the Figure 11 verifier equations and, as in CGGMP21, guarantees
only the widened range determined by the slack parameter. It also binds the
plaintext to an integer commitment using a Ring-Pedersen commitment key.

The honest-prover relation checked before proof generation is:

$$
R_{\mathrm{enc}} =
\left\{
\left( (N, \hat{N}, s, t, K),\; (k,\rho) \right)
\;\middle|\;
K = \operatorname{Enc}_N(k; \rho),\;
k \in [-2^l, 2^l)
\right\}.
$$

Verification proves the corresponding widened statement: under the setup
assumptions from CGGMP21, an accepting transcript guarantees that the encrypted
plaintext lies in $[-2^{l+\epsilon}, 2^{l+\epsilon})$.

## Input

The prover has witness $(k,\rho)$ where $K = \operatorname{Enc}_N(k;\rho)$.

The verifier has statement $K$, the Paillier public key $N$, and the Ring-Pedersen commitment key $(\hat{N},s,t)$.

Both parties use:

* $l$ - the witness range parameter, exposed as `rangeBits`,
* $\epsilon$ - the proof slack parameter, exposed as `slackBits`.

All bit lengths accepted by the constructor are byte-aligned.

## Protocol

1. Prover samples:

$$
\alpha \leftarrow [-2^{l+\epsilon}, 2^{l+\epsilon}),\qquad
\mu \leftarrow [-2^{l+|\hat{N}|}, 2^{l+|\hat{N}|}),\qquad
\gamma \leftarrow [-2^{l+\epsilon+|\hat{N}|}, 2^{l+\epsilon+|\hat{N}|})
$$

and a Paillier nonce $r$.

2. Prover sends:

$$
S = \operatorname{Com}_{\hat{N}}(k;\mu),\qquad
A = \operatorname{Enc}_N(\alpha;r),\qquad
C = \operatorname{Com}_{\hat{N}}(\alpha;\gamma).
$$

3. Verifier sends challenge $e$.

4. Prover responds with:

$$
z_1 = \alpha + ek,\qquad
z_2 = r\rho^e,\qquad
z_3 = \gamma + e\mu.
$$

5. Verifier accepts iff:

$$
z_1 \in [-2^{l+\epsilon}, 2^{l+\epsilon}),\qquad
\operatorname{Enc}_N(z_1;z_2) = A K^e,\qquad
\operatorname{Com}_{\hat{N}}(z_1;z_3) = C S^e.
$$

## Implementation notes

`NewProtocol` checks that the Paillier modulus bit length, the Ring-Pedersen
modulus bit length, `rangeBits`, and `slackBits` are all multiples of 8. The
samplers use byte-aligned two's-complement encodings and then prepend a random
sign-extension byte, producing values in $[-2^b, 2^b)$.

The implementation uses a 128-bit two's-complement challenge, exposed by
`challengeBitsLength`, rather than the curve-order challenge domain used in
CGGMP21 Figure 11. `SoundnessError` therefore reports 128 bits. The constructor
requires `slackBits` to cover both this challenge length and the configured
witness range with an additional computational-security margin.

`inSignedBitRange` intentionally rejects the lower endpoint $-2^b$ by checking
`abs(x).TrueLen() <= b`. This is a conservative choice: the sampler reaches
that endpoint with probability $2^{-(b+1)}$, which is negligible for the
parameter sizes accepted by the constructor.

The Paillier modulus check requires the widened response bound $2^{l+\epsilon}$
to fit inside the symmetric Paillier plaintext interval.

## Simulator

The simulator samples $(z_1,z_2,z_3)$ directly, then derives $(S,A,C)$ so that
the verifier equations hold for the supplied challenge. This matches the usual
honest-verifier zero-knowledge simulator shape for sigma protocols.

## Reference

[CGGMP21](https://eprint.iacr.org/2021/060.pdf), Figure 11, "Paillier Encryption in Range ZK".
