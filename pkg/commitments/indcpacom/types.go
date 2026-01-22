package indcpacom

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/errs-go/errs"
)

// Commitment represents an IND-CPA commitment, which is the ciphertext resulting
// from encrypting the committed message.
type Commitment[C encryption.ReRandomisableCiphertext[C, N, PK], N interface {
	encryption.Nonce
	algebra.Operand[N]
}, PK encryption.PublicKey[PK]] struct {
	v C
}

// Value returns the underlying ciphertext of the commitment.
func (c *Commitment[C, N, PK]) Value() C {
	return c.v
}

// Equal returns true if two commitments are equal (i.e., contain equal ciphertexts).
func (c *Commitment[C, N, PK]) Equal(other *Commitment[C, N, PK]) bool {
	if c == nil || other == nil {
		return c == other
	}
	return c.v.Equal(other.v)
}

// ReRandomiseWithWitness re-randomises the commitment using the provided witness.
// This produces a new commitment to the same message with different randomness.
// The same witness will always produce the same re-randomised commitment.
// Returns an error if the key or witness is nil.
func (c *Commitment[C, N, PK]) ReRandomiseWithWitness(k *Key[PK], w *Witness[N]) (*Commitment[C, N, PK], error) {
	if k == nil || w == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	newCiphertext, err := c.v.ReRandomiseWithNonce(k.v, w.v)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot re-randomise commitment")
	}
	return &Commitment[C, N, PK]{v: newCiphertext}, nil
}

// ReRandomise re-randomises the commitment using fresh randomness from prng.
// This produces a new commitment to the same message with different randomness,
// along with the witness used for re-randomisation.
// Returns an error if the key or prng is nil.
func (c *Commitment[C, N, PK]) ReRandomise(k *Key[PK], prng io.Reader) (*Commitment[C, N, PK], *Witness[N], error) {
	if k == nil || prng == nil {
		return nil, nil, ErrIsNil.WithStackFrame()
	}
	newCiphertext, newNonce, err := c.v.ReRandomise(k.v, prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot re-randomise commitment")
	}
	return &Commitment[C, N, PK]{v: newCiphertext}, &Witness[N]{v: newNonce}, nil
}

// Key wraps the public key used for the IND-CPA commitment scheme.
type Key[PK encryption.PublicKey[PK]] struct {
	v PK
}

// Value returns the underlying public key.
func (k *Key[PK]) Value() PK {
	return k.v
}

// NewKey creates a new Key from a public key.
// Returns an error if the provided public key is nil.
func NewKey[PK encryption.PublicKey[PK]](v PK) (*Key[PK], error) {
	if utils.IsNil(v) {
		return nil, ErrIsNil.WithStackFrame()
	}
	return &Key[PK]{v: v}, nil
}

// Message wraps a plaintext value to be committed.
type Message[M encryption.Plaintext] struct {
	v M
}

// Value returns the underlying plaintext.
func (m *Message[M]) Value() M {
	return m.v
}

// NewMessage creates a new Message from a plaintext value.
// Returns an error if the provided plaintext is nil.
func NewMessage[M encryption.Plaintext](v M) (*Message[M], error) {
	if utils.IsNil(v) {
		return nil, ErrIsNil.WithStackFrame()
	}
	return &Message[M]{v: v}, nil
}

// Witness wraps the nonce/randomness used in the commitment.
// The witness is required to open (verify) a commitment.
type Witness[N interface {
	encryption.Nonce
	algebra.Operand[N]
}] struct {
	v N
}

// Value returns the underlying nonce.
func (w *Witness[N]) Value() N {
	return w.v
}

// Op combines two witnesses by applying the underlying nonce operation.
// This is used to compute the combined witness needed to verify a re-randomised
// commitment: if C' = ReRandomise(C, r'), then Verify(C', m, w.Op(w')) succeeds
// where w is the original witness and w' is the re-randomization witness.
// Panics if other is nil.
func (w *Witness[N]) Op(other *Witness[N]) *Witness[N] {
	if other == nil {
		panic(ErrIsNil.WithStackFrame())
	}
	return &Witness[N]{v: w.v.Op(other.v)}
}

// NewWitness creates a new Witness from a nonce value.
// Returns an error if the provided nonce is nil.
func NewWitness[N interface {
	encryption.Nonce
	algebra.Operand[N]
}](v N) (*Witness[N], error) {
	if utils.IsNil(v) {
		return nil, ErrIsNil.WithStackFrame()
	}
	return &Witness[N]{v: v}, nil
}

// Errors returned by the indcpacom package.
var (
	// ErrIsNil is returned when a required value is nil.
	ErrIsNil = errs.New("value is nil")
	// ErrVerificationFailed is returned when commitment verification fails.
	ErrVerificationFailed = errs.New("commitment verification failed")
	// ErrInvalidType is returned when a type assertion fails.
	ErrInvalidType = errs.New("invalid type")
)
