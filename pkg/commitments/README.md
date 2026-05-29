# Commitments

This package defines the common interfaces, error sentinels, and generic helpers
for commitment schemes; the concrete schemes live in subpackages.

A commitment scheme lets a committer publish a value `C` binding them to a message
`m` (chosen with secret randomness, the *witness* `w`), and later *open* `C` by
revealing `(m, w)`. The two security properties are:

- **Hiding**: `C` reveals nothing about `m` (until opened).
- **Binding**: the committer cannot open `C` to a different message.

No scheme achieves both perfectly; each implementation fixes one as perfect/
statistical and the other as computational.

## Core interfaces

- `CommitmentKey`: the public parameter of a scheme. `CommitWithWitness(m, w)`
  produces a commitment deterministically; `Open(C, m, w)` verifies an opening
  (returning `ErrVerificationFailed` on mismatch). `SampleWitness` draws fresh
  randomness.
- `TrapdoorKey`: a `CommitmentKey` plus a secret trapdoor. `Equivocate` opens an
  existing commitment to a different message, so binding does **not** hold for a
  trapdoor holder — this is the standard simulation tool in security proofs.
  `Export` returns the public key with the trapdoor removed.
- `Homomorphic` / `GroupHomomorphic`: schemes where messages, witnesses, and
  commitments carry algebraic operations and committing is a homomorphism, so
  commitments can be combined (`CommitmentOp`), scaled (`CommitmentScalarOp`),
  shifted (`Shift`), and re-randomised (`ReRandomise`) without opening. The
  `GroupHomomorphic` variant exposes the underlying groups (Group rather than
  FiniteGroup, so unknown-order groups are supported).
- The `…CommitmentKey` / `…TrapdoorKey` combinations layer these together.

`Message`, `Witness`, and `Commitment` are the (scheme-defined) plaintext,
randomness, and output types; the witness is secret, the commitment is public.

## Helpers

- `Commit(key, message, prng)`: samples a fresh witness and returns
  `(commitment, witness)`.
- `ReRandomise(key, commitment, prng)`: blinds a commitment to the same message and
  returns the new commitment and the freshly sampled witness **shift** — to open
  the result, combine the original witness with this shift via `key.WitnessOp`.

## Implementations

- `pedersen` — `g^m·h^r` over a prime-order group. **Perfectly hiding**,
  computationally binding (discrete log). Additively homomorphic; has a trapdoor.
- `intcom` — `s^m·t^r mod N̂`, the CGGMP21 ring-Pedersen integer commitment.
  **Statistically hiding**, computationally binding (factoring). Additively
  homomorphic; has a trapdoor.
- `indcpacom` — `Enc_ek(m; r)` from any IND-CPA encryption scheme.
  **Computationally hiding** (IND-CPA), binding by unique decryption. Homomorphic
  when the underlying cipher is.
- `hashcom` — keyed hash `H_k(m‖r)`. Computationally hiding, binding from collision
  resistance. Not homomorphic.
