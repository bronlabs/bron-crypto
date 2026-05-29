# IND-CPA Commitments (commitment from encryption)

A commitment to a message `m` with witness `r` is the ciphertext

```text
C = Enc_ek(m; r)
```

produced by encrypting `m` under a public encryption key `ek` with nonce `r`. The
commitment key is exactly that encryption key, so the scheme works for any
IND-CPA encryption scheme implementing `pkg/encryption`.

- **Hiding** is computational, resting on the IND-CPA security of the encryption
  scheme: a ciphertext reveals nothing about `m` to anyone without the decryption
  key. It depends on `r` being a fresh, secret nonce.
- **Binding** is on the message: a ciphertext decrypts to at most one plaintext, so
  a commitment cannot be opened to two different messages. Binding is therefore as
  strong as the encryption scheme's decryption correctness (perfect for
  perfectly-correct schemes). This is the dual of Pedersen, which is perfectly
  hiding and only computationally binding.

> **Trapdoor / extractability.** Whoever holds the matching **decryption key** can
> decrypt the commitment and recover `m` (and, with an `OpeningKey`, also `r`),
> defeating hiding. The decryption key therefore must remain unknown to verifiers.
> This same property makes the construction a useful *extractable* commitment in
> MPC: a simulator holding the decryption key can extract committed values.

## Types

- `CommitmentKey`: wraps a public `encryption.EncryptionKey`. Holds no secret.
- `HomomorphicCommitmentKey`: wraps a `HomomorphicEncryptionKey` and additionally
  exposes the induced homomorphism on messages, witnesses, and commitments.
- `Message`: the plaintext `m`.
- `Witness`: the secret encryption nonce `r`. Keep private until opening.
- `Commitment`: the ciphertext `Enc_ek(m; r)`.

All types implement CBOR encoding; decoding routes through the constructors, with
ciphertext/key well-formedness delegated to the underlying encryption types.

There is no `TrapdoorKey` type here — the encryption scheme's `DecryptionKey` /
`OpeningKey` (in `pkg/encryption`) plays that role.

## Commit, Open, Re-randomise

- `key.CommitWithWitness(message, witness)`: deterministic `Enc_ek(m; r)`.
- `commitments.Commit(key, message, prng)`: samples a fresh nonce and returns
  `(commitment, witness)`.
- `key.Open(commitment, message, witness)`: re-encrypts and compares the
  ciphertext, returning `commitments.ErrVerificationFailed` on mismatch.

## Homomorphism

With a homomorphic encryption scheme, `CommitmentOp` combines commitments via the
ciphertext homomorphism, yielding a commitment to the combined message under the
combined nonce; `MessageOp`/`WitnessOp` and the `…ScalarOp` / `…OpInv` variants
apply the matching plaintext/nonce operations. `ReRandomise(commitment,
witnessShift)` blinds a commitment to the same message, and `Shift(commitment,
message)` adds to the committed value while keeping the witness. These make the
scheme suitable for aggregation and linear proof systems.
