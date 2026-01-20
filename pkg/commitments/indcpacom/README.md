# indcpacom

IND-CPA commitment scheme constructed from encryption.

## Overview

This package implements a commitment scheme based on any IND-CPA (indistinguishability under chosen-plaintext attack) secure encryption scheme. The construction is:

- **Commit(m)** = Encrypt(m, r) using randomness r
- **Commitment** = the resulting ciphertext
- **Witness** = the encryption nonce/randomness r

## Security Properties

- **Hiding**: Inherited from the semantic security of the encryption scheme
- **Binding**: Inherited from the correctness of decryption
- **Re-randomizable**: Commitments can be re-randomized to produce new commitments to the same message

## Usage

```go
import (
    "crypto/rand"

    "github.com/bronlabs/bron-crypto/pkg/commitments/indcpacom"
    "github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
)

// Setup: create encryption scheme and generate keys
paillierScheme := paillier.NewScheme()
kg, _ := paillierScheme.Keygen()
_, pk, _ := kg.Generate(rand.Reader)

// Create commitment scheme
key, _ := indcpacom.NewKey(pk)
scheme, _ := indcpacom.NewScheme(paillierScheme, key)

// Commit to a message
plaintext, _ := pk.PlaintextSpace().Sample(nil, nil, rand.Reader)
message, _ := indcpacom.NewMessage(plaintext)

committer, _ := scheme.Committer()
commitment, witness, _ := committer.Commit(message, rand.Reader)

// Verify the commitment
verifier, _ := scheme.Verifier()
err := verifier.Verify(commitment, message, witness)
// err == nil if verification succeeds

// Re-randomize a commitment
newCommitment, rerandWitness, _ := commitment.ReRandomise(key, rand.Reader)

// Verify re-randomized commitment using combined witness
combinedWitness := witness.Op(rerandWitness)
err = verifier.Verify(newCommitment, message, combinedWitness)
```

## Deterministic Commitments

For protocols requiring deterministic commitment creation:

```go
// Create witness from a known nonce
nonce, _ := pk.NonceSpace().Sample(rand.Reader)
witness, _ := indcpacom.NewWitness(nonce)

// Commit deterministically
commitment, _ := committer.CommitWithWitness(message, witness)
```

## Witness Combination

When a commitment is re-randomized, verifying the new commitment requires combining the original witness with the re-randomization witness using the `Op` method:

```go
// Original commitment with witness
commitment, witness, _ := committer.Commit(message, rand.Reader)

// Re-randomize
newCommitment, rerandWitness, _ := commitment.ReRandomise(key, rand.Reader)

// Combine witnesses to verify re-randomized commitment
combinedWitness := witness.Op(rerandWitness)
verifier.Verify(newCommitment, message, combinedWitness)

// Multiple re-randomizations chain the witness combinations
commitment2, rerandWitness2, _ := newCommitment.ReRandomise(key, rand.Reader)
combinedWitness2 := combinedWitness.Op(rerandWitness2)
verifier.Verify(commitment2, message, combinedWitness2)
```
