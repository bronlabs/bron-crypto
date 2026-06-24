# Pedersen Commitments

Prime-order Pedersen commitments. A commitment to a scalar message `m` with
randomness `r` is the single group element

```
C = g^m · h^r
```

over a prime-order group with two generators `g` and `h`. The scheme is
**perfectly hiding** (for uniform secret `r`, `C` is uniform and independent of
`m`) and **computationally binding** under the discrete-log assumption — provided
nobody knows `log_g(h)`. It is additively homomorphic and re-randomisable.

## Types

- `CommitmentKey`: the public common reference string — the generators `g` and
  `h`. Holds no secret.
- `TrapdoorKey`: a `CommitmentKey` plus the secret `lambda = log_g(h)`. Its holder
  can equivocate, so it is **not binding** against them; share only the exported
  public key.
- `Message`: the committed scalar `m`.
- `Witness`: the secret randomness `r`. Keep private until opening.
- `Commitment`: the group element `g^m · h^r`.

All five implement CBOR encoding. Decoding routes through the constructors, so a
decoded value is structurally valid; however, `CommitmentKey` decoding cannot
verify the unknown-discrete-log precondition (see below).

## Key Generation

Binding fails if the committer knows `lambda` with `h = g^lambda`. Generate keys
so that relation stays unknown:

- `SampleCommitmentKey(group, prng)`: samples `h` as a uniformly random group
  element (not as `g^r`), so `log_g(h)` is unknown to the caller. Pairs it with
  the canonical generator `g`.
- `ExtractCommitmentKey(transcript, label, basePoint)`: derives `h` by hashing
  transcript output into the group (nothing-up-my-sleeve) and uses `basePoint` as
  `g`. Reproducible by all parties sharing the transcript; `label`
  domain-separates the generator.
- `NewCommitmentKeyUnchecked(g, h)`: only rejects nil, identical, or identity
  generators. Use it **only** when the unknown-discrete-log relation has been
  established by a trusted setup or ceremony. A `CommitmentKey` from an untrusted
  source — including one decoded from CBOR — must not be accepted as a binding CRS.

For testing or simulation, `SampleTrapdoorKey(group, prng)` / `NewTrapdoorKey(g,
lambda)` produce a key whose trapdoor is deliberately known.

## Commit, Open, Re-randomise

- `key.CommitWithWitness(message, witness)`: deterministic `C = g^m · h^r`.
- `commitments.Commit(key, message, prng)`: samples a fresh witness and returns
  `(commitment, witness)`.
- `key.Open(commitment, message, witness)`: recomputes and compares, returning
  `commitments.ErrVerificationFailed` on mismatch.
- `key.ReRandomise(commitment, witnessShift)` / `commitments.ReRandomise(key,
  commitment, prng)`: blind a commitment with extra randomness, yielding an
  unlinkable commitment to the same message.

## Homomorphism

`CommitmentOp` multiplies commitments, which adds the underlying messages and
witnesses; `MessageOp`/`WitnessOp` and the `…ScalarOp` / `…OpInv` variants apply
the matching field operations. `Shift(commitment, message)` adds `message · g`,
changing the committed value while keeping the witness. These make the scheme
suitable for aggregation and linear proof systems.

## Trapdoor

A `TrapdoorKey` can `Equivocate(message, witness, newMessage, prng)`, computing a
witness `r'` that opens an existing commitment to a different message via
`r' = r + lambda^{-1}(m − m')`. This is the standard simulation tool; it also
demonstrates why `lambda` must stay secret. `Export()` returns the public
`CommitmentKey` without the trapdoor.

## Reference

<!-- paper: docs/papers/ped91.pdf -->
- [Pedersen, T.P. (1992). Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing.](https://link.springer.com/chapter/10.1007/3-540-46766-1_9)