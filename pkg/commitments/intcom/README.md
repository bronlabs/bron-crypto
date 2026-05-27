# Bounded Integer Commitments (CGGMP21 ring-Pedersen)

A commitment to an integer message `m` with integer randomness `r` is the single
RSA-group element

```text
C = s^m · t^r mod N̂
```

where `N̂ = p·q` is a product of safe primes and `s`, `t` generate the cyclic group
`QR(N̂)` of quadratic residues. This is the ring-Pedersen commitment used
throughout the CGGMP21 ZK proofs (range proofs, Π^enc, Π^aff-g, …).

Unlike prime-order Pedersen, the message is an arbitrary **integer**, not a field
element, which is what makes it usable as the base for integer range proofs.

- **Binding** is computational: opening one commitment to two messages reveals
  `log_t(s)`, so binding rests on the factoring / discrete-log assumption in
  `QR(N̂)`. The trapdoor is `λ = log_t(s)`.
- **Hiding** is statistical: the witness `r` is sampled from `[−N̂·2^κ, N̂·2^κ)`
  (κ = statistical security parameter), a range far wider than `ord(t)`, so
  `r mod ord(t)` is statistically close to uniform.
- The scheme is additively homomorphic and re-randomisable.

## Types

- `CommitmentKey`: the public key — generators `s`, `t` of `QR(N̂)`. Holds no
  secret. Also caches the witness sampling bounds.
- `TrapdoorKey`: a `CommitmentKey` plus the secret `λ = log_t(s)` and the modulus
  factorisation (a known-order view of the group). Its holder can equivocate and
  is **not bound**; share only the key returned by `Export()`.
- `Message`: the committed integer `m`.
- `Witness`: the secret integer randomness `r`. Keep private until opening.
- `Commitment`: the group element `s^m · t^r`.

All implement CBOR encoding. Decoding routes through the constructors, but in the
unknown-order setting only Jacobi (`torsion-free`) and generator (`gcd(x−1, N̂)=1`)
checks are possible — full `QR(N̂)` membership cannot be verified, so a decoded
`CommitmentKey` from an untrusted source must not be assumed binding without an
accompanying Π^prm-style proof.

## Key Generation

Binding fails if the committer knows `λ` with `s = t^λ`. Generate keys so that
relation stays unknown:

- `SampleCommitmentKey(keyLen, prng)`: samples a safe-prime group and generators
  `s = t^λ`, then discards `λ` and the factorisation so the key is binding.
- `ExtractCommitmentKey(transcript, label, group)`: derives `s` and `t`
  deterministically from a public transcript (nothing-up-my-sleeve), so all
  parties sharing the transcript agree on the same trapdoor-free key. Each
  generator is the square of a hashed-to-group value (forcing it into `QR(N̂)`) and
  must satisfy `gcd(x−1, N̂)=1`; `label` domain-separates the two.
- `SampleTrapdoorKey(keyLen, prng)` / `NewTrapdoorKey(t, λ)`: produce a key whose
  trapdoor is deliberately retained (for testing or simulation).

`SamplePedersenParameters` exposes the full setup, including the secret primes and
`λ`; its doc comment details the safe-prime, generator, and `λ`-unit requirements.

## Commit, Open, Re-randomise

- `key.CommitWithWitness(message, witness)`: deterministic `C = s^m · t^r`.
- `commitments.Commit(key, message, prng)`: samples a fresh witness and returns
  `(commitment, witness)`.
- `key.Open(commitment, message, witness)`: recomputes and compares, returning
  `commitments.ErrVerificationFailed` on mismatch.
- `key.ReRandomise(commitment, witnessShift)`: multiplies by `t^witnessShift`,
  yielding a commitment to the same message; draw the shift from the full witness
  range for unlinkability.

## Homomorphism

`CommitmentOp` multiplies commitments, adding the underlying messages and
witnesses; `MessageOp`/`WitnessOp` and the `…ScalarOp` / `…OpInv` variants apply
the matching integer operations. `Shift(commitment, message)` multiplies by
`s^message`, changing the committed value while keeping the witness. `TrapdoorKey`
overrides these to use the known group order for speed; the results are identical
to the public-key versions.

## Trapdoor

`TrapdoorKey.Equivocate(message, witness, newMessage, prng)` computes a witness
`r'` opening an existing commitment to `newMessage`. The raw solution is
`r' = r + λ·(m − m')`; because that shifts the distribution of `r'`, the method
then re-randomises `r'` over its residue class mod `ord(t)` so the result matches
a freshly sampled opening — which is why a `prng` is required (in contrast to the
prime-order Pedersen trapdoor, whose shift is already uniform). `Lambda()` exposes
the secret trapdoor; `Export()` returns the public key without it.

## Reference

<!-- paper: docs/papers/2021-060_20241021_172019.pdf -->
- [Canetti, Gennaro, Goldfeder, Makriyannis, Peled (2021). UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts (CGGMP21).](https://eprint.iacr.org/2021/060)
