# lindell17

This package implements two-party Lindell17 threshold ECDSA from [Lin17][1].
Long-term key shares use the repository's MSP-based Feldman representation,
which is an adaptation of the protocol in the paper.

The DKG path proves bounded Paillier encryptions of every raw MSP share
component. The trusted-dealer path encrypts the same components without those
proofs and therefore relies on the dealer being trusted. Both paths store the
encrypted vectors only for qualified two-shareholder peers.

Signing converts the selected quorum to additive sharing and refreshes it with
pseudorandom zero sharing (PRZS). Both steps follow the approach used by the
repository's [DKLS23][2] implementation. They adapt Lindell17 to the
repository's sharing model and are not steps in the paper's original
two-party key-sharing formulation.

The encrypted primary share is converted without constructing a large
integer-lifted Paillier plaintext: signing combines each MSP reconstruction
coefficient with the Lindell signing multiplier modulo the curve order before
applying it to the corresponding ciphertext.

Only qualified two-shareholder quorums receive Lindell17 auxiliary material. A
general monotone access structure may therefore contain shareholders or larger
qualified sets that cannot run this two-party signing protocol.

## Operational requirements

- Signing requires exactly two authorized shareholders and accepts only the
  Fischlin or Randomised Fischlin non-interactive compiler. Fiat-Shamir is not
  accepted because Lindell17 signing requires straight-line extraction. Both
  parties must select the same compiler.
- Production DKG and trusted-dealer setup require Paillier moduli of at least
  3072 bits (`base.IFCKeyLength`). DKG's `DefaultPaillierKeyLen` selects this
  value. All DKG participants must agree on the key length and compiler.
- Every caller-provided `io.Reader` must be a cryptographically secure random
  source. The DKG reader must also be safe for concurrent use because proof
  batching may read from it concurrently; `crypto/rand.Reader` satisfies both
  requirements.
- Callers are responsible for session orchestration, authenticated channels,
  and handling aborts; this package does not provide fairness or guaranteed
  output.

See the [signing documentation](./signing/) for the Paillier no-wrap bounds that
depend on the curve order and the number of MSP components.

## Security and audit scope

The MSP storage, signing-time conversion, and PRZS refresh described above are
repository adaptations and are not covered directly by the security statement
for the paper's original key-sharing formulation. The January 2026 Trail of
Bits report in the repository's [`audits`](../../../../../audits/) directory
reviewed an earlier Lindell17 implementation and recommended additional review
once the Lindell17 and Paillier implementations were stable. The current MSP
adaptation postdates the reviewed version and should be treated as a post-audit
delta.

[1]: <https://eprint.iacr.org/2017/552>
[2]: <https://eprint.iacr.org/2023/765>
