package indcpacom

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

// CommitterOption is a functional option for configuring a Committer.
type CommitterOption[
	N interface {
		encryption.Nonce
		algebra.Operand[N]
	}, P encryption.Plaintext, CX encryption.ReRandomisableCiphertext[CX, N, PK],
	PK encryption.PublicKey[PK],
] = func(*Committer[N, P, CX, PK]) error

// Committer creates IND-CPA commitments by encrypting messages.
type Committer[
	N interface {
		encryption.Nonce
		algebra.Operand[N]
	}, P encryption.Plaintext, CX encryption.ReRandomisableCiphertext[CX, N, PK],
	PK encryption.PublicKey[PK],
] struct {
	key *Key[PK]
	enc encryption.LinearlyRandomisedEncrypter[PK, P, CX, N]
}

// Commit creates a commitment to the given message using fresh randomness from prng.
// Returns the commitment and the witness (nonce) needed to open it.
// Returns an error if the message or prng is nil.
func (c *Committer[N, P, CX, PK]) Commit(
	message *Message[P],
	prng io.Reader,
) (*Commitment[CX, N, PK], *Witness[N], error) {
	if message == nil || prng == nil {
		return nil, nil, ErrIsNil.WithStackFrame()
	}
	ciphertext, nonce, err := c.enc.Encrypt(message.Value(), c.key.Value(), prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot encrypt message for commitment")
	}
	return &Commitment[CX, N, PK]{v: ciphertext}, &Witness[N]{v: nonce}, nil
}

// CommitWithWitness creates a commitment to the given message using the provided witness.
// This allows for deterministic commitment creation when the same witness is used.
// Returns an error if the message or witness is nil.
func (c *Committer[N, P, CX, PK]) CommitWithWitness(
	message *Message[P],
	witness *Witness[N],
) (*Commitment[CX, N, PK], error) {
	if message == nil || witness == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	ciphertext, err := c.enc.EncryptWithNonce(message.Value(), c.key.Value(), witness.Value())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot encrypt message for commitment with witness")
	}
	return &Commitment[CX, N, PK]{v: ciphertext}, nil
}

// VerifierOption is a functional option for configuring a Verifier.
type VerifierOption[
	N interface {
		encryption.Nonce
		algebra.Operand[N]
	}, P encryption.Plaintext, CX encryption.ReRandomisableCiphertext[CX, N, PK],
	PK encryption.PublicKey[PK],
] = func(*Verifier[N, P, CX, PK]) error

// Verifier verifies IND-CPA commitments by re-computing the commitment from
// the message and witness and comparing it to the provided commitment.
type Verifier[
	N interface {
		encryption.Nonce
		algebra.Operand[N]
	}, P encryption.Plaintext, CX encryption.ReRandomisableCiphertext[CX, N, PK],
	PK encryption.PublicKey[PK],
] struct {
	c *commitments.GenericVerifier[
		*Committer[N, P, CX, PK],
		*Witness[N],
		*Message[P],
		*Commitment[CX, N, PK],
	]
}

// Verify checks that the commitment is valid for the given message and witness.
// It re-computes the commitment from the message and witness and compares it
// to the provided commitment. Returns nil if verification succeeds, or an error
// if verification fails.
func (v *Verifier[N, P, CX, PK]) Verify(
	commitment *Commitment[CX, N, PK],
	message *Message[P],
	witness *Witness[N],
) error {
	if err := v.c.Verify(commitment, message, witness); err != nil {
		return errs.Wrap(err).WithMessage("IND-CPA commitment verification failed")
	}
	return nil
}
