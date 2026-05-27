package indcpacom

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

// NewCommitment wraps a ciphertext as a commitment value, rejecting nil. It is the
// canonical constructor and is used by the CBOR decoder.
func NewCommitment[C encryption.Ciphertext[C]](c C) (*Commitment[C], error) {
	if utils.IsNil(c) {
		return nil, commitments.ErrIsNil.WithMessage("ciphertext must not be nil")
	}
	return &Commitment[C]{c: c}, nil
}

// Commitment is the ciphertext Enc_ek(m; r) that serves as the commitment. It is
// computationally hiding under the IND-CPA security of the encryption scheme and
// binding on the message because a ciphertext decrypts to at most one plaintext —
// so binding is as strong as the scheme's decryption correctness (perfect for
// perfectly-correct schemes). A holder of the matching decryption key can recover
// m, so hiding holds only against parties without it.
type Commitment[C encryption.Ciphertext[C]] struct {
	c C
}

type commitmentDTO[C encryption.Ciphertext[C]] struct {
	C C `cbor:"c"`
}

// Value returns the underlying ciphertext.
func (c *Commitment[C]) Value() C {
	return c.c
}

// Equal reports whether two commitments hold equal ciphertexts, treating a nil
// commitment as equal only to another nil one. Commitments are public, so this
// need not be constant time.
func (c *Commitment[C]) Equal(other *Commitment[C]) bool {
	if c == nil || other == nil {
		return c == other
	}
	return c.c.Equal(other.c)
}

// MarshalCBOR encodes the commitment's ciphertext.
func (c *Commitment[C]) MarshalCBOR() ([]byte, error) {
	out, err := serde.MarshalCBOR(&commitmentDTO[C]{C: c.c})
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal commitment")
	}
	return out, nil
}

// UnmarshalCBOR decodes a commitment, rejecting a nil ciphertext via NewCommitment.
// This is a deserialization trust boundary; ciphertext well-formedness is enforced
// by the ciphertext decoder.
func (c *Commitment[C]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*commitmentDTO[C]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal commitment")
	}
	cc, err := NewCommitment(dto.C)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid commitment value in unmarshalled data")
	}
	*c = *cc
	return nil
}

// NewWitness wraps an encryption nonce as commitment randomness, rejecting nil.
func NewWitness[S encryption.Nonce](s S) (*Witness[S], error) {
	if utils.IsNil(s) {
		return nil, commitments.ErrIsNil.WithMessage("witness value must not be nil")
	}
	return &Witness[S]{s: s}, nil
}

// Witness is the secret encryption nonce r used to form the commitment
// Enc_ek(m; r). The IND-CPA hiding argument relies on this nonce being fresh and
// secret; keep it private until opening.
type Witness[N encryption.Nonce] struct {
	s N
}

type witnessDTO[N encryption.Nonce] struct {
	S N `cbor:"s"`
}

// Value returns the underlying nonce. The result is secret.
func (w *Witness[N]) Value() N {
	return w.s
}

// MarshalCBOR encodes the witness nonce. The output is secret material.
func (w *Witness[N]) MarshalCBOR() ([]byte, error) {
	out, err := serde.MarshalCBOR(&witnessDTO[N]{S: w.s})
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal witness")
	}
	return out, nil
}

// UnmarshalCBOR decodes a witness nonce, rejecting nil via NewWitness. This is a
// deserialization trust boundary for secret material.
func (w *Witness[N]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*witnessDTO[N]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal witness")
	}
	ww, err := NewWitness(dto.S)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid witness value in unmarshalled data")
	}
	*w = *ww
	return nil
}

// NewMessage wraps a plaintext as the committed value, rejecting nil.
func NewMessage[P encryption.Plaintext](m P) (*Message[P], error) {
	if utils.IsNil(m) {
		return nil, commitments.ErrIsNil.WithMessage("message value must not be nil")
	}
	return &Message[P]{m: m}, nil
}

// Message is the committed value m, a plaintext of the underlying encryption
// scheme.
type Message[P encryption.Plaintext] struct {
	m P
}

type messageDTO[P encryption.Plaintext] struct {
	M P `cbor:"m"`
}

// Value returns the underlying plaintext m.
func (m *Message[P]) Value() P {
	return m.m
}

// MarshalCBOR encodes the message plaintext.
func (m *Message[P]) MarshalCBOR() ([]byte, error) {
	out, err := serde.MarshalCBOR(&messageDTO[P]{M: m.m})
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal message")
	}
	return out, nil
}

// UnmarshalCBOR decodes a message plaintext, rejecting nil via NewMessage.
func (m *Message[P]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*messageDTO[P]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal message")
	}
	mm, err := NewMessage(dto.M)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid message value in unmarshalled data")
	}
	*m = *mm
	return nil
}
