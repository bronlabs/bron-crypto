# lindell17/keygen/dkg

This package implements Lindell17 auxiliary-information distributed key
generation over an existing MSP-based ECDSA base shard. It runs over the
complete shareholder set but creates signing material only for qualified
two-party quorums.

Each participant independently decomposes every component `x_r` of its raw MSP
share as `x_r = 3x'_r + x''_r mod q`, with both `x'_r` and `x''_r` in
`[q/3, 2q/3)`. The decomposition points and proofs are ordered and
domain-separated by their absolute MSP row identifiers. Each participant uses
one Paillier key and encrypts every decomposition half once with a fresh nonce.
The accompanying checks have separate responsibilities:

- LP proves that the Paillier modulus is well formed;
- LPDL proves that each ciphertext encrypts the discrete logarithm of its
  committed curve point;
- compiled Schnorr proofs establish knowledge of the decomposition discrete
  logarithms; and
- a direct curve-point check establishes that `3Q'_r + Q''_r` equals the public
  raw MSP-share component at row `r`.

The LP proof runs once per qualified prover/verifier pair; LPDL runs for both
halves of every component. Proof roles, decomposition halves, absolute row
identifiers, the Paillier key, curve point, and ciphertext are bound into the
relevant transcript. The resulting shard stores, for each qualified peer, the
peer's Paillier public key and vector of encrypted raw MSP-share components.
Signing applies the selected two-party quorum's MSP reconstruction coefficients
component-wise under encryption when it converts those shares to additive form.

## Operational requirements

- The session quorum must be the complete MSP shareholder set, even though
  auxiliary material is retained only for qualified two-party quorums.
- Production deployments must use a Paillier modulus of at least 3072 bits.
  `DefaultPaillierKeyLen` selects this value.
- The caller-provided `io.Reader` must be cryptographically secure and safe for
  concurrent use because proof batching may read from it concurrently;
  `crypto/rand.Reader` satisfies both requirements.
- The non-interactive compiler is caller-selected and must be supported by the
  compiler package. Signing has the stricter requirement that it use Fischlin
  or Randomised Fischlin.
- All participants in one DKG session must use the same Paillier key length and
  non-interactive compiler.
