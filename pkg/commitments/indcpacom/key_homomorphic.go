package indcpacom

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

// NewHomomorphicCommitmentKey builds a homomorphic commitment key from a
// homomorphic encryption key, rejecting nil. The commitment inherits the
// encryption scheme's homomorphism, so operating on commitments mirrors operating
// on the underlying plaintexts and nonces.
func NewHomomorphicCommitmentKey[
	EK encryption.HomomorphicEncryptionKey[EK, P, N, C, S],
	P encryption.Plaintext,
	N encryption.Nonce,
	C encryption.Ciphertext[C],
	S any,
](encryptionKey EK) (*HomomorphicCommitmentKey[EK, P, N, C, S], error) {
	commitmentKey, err := NewCommitmentKey(encryptionKey)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create commitment key from encryption key")
	}
	return &HomomorphicCommitmentKey[EK, P, N, C, S]{CommitmentKey: *commitmentKey}, nil
}

// HomomorphicCommitmentKey is a CommitmentKey backed by a homomorphic encryption
// scheme, exposing the induced homomorphism on messages, witnesses, and
// commitments. The opening of a combined commitment is obtained by combining the
// component messages (MessageOp) and witnesses (WitnessOp) with the matching
// operations. It carries the same binding/hiding properties (and decryption-key
// trapdoor) as the embedded CommitmentKey.
type HomomorphicCommitmentKey[
	EK encryption.HomomorphicEncryptionKey[EK, P, N, C, S],
	P encryption.Plaintext,
	N encryption.Nonce,
	C encryption.Ciphertext[C],
	S any,
] struct {
	CommitmentKey[EK, P, N, C]
}

// WitnessOp combines nonces with the encryption scheme's nonce operation. The
// result is the witness that opens the CommitmentOp of the corresponding
// commitments.
func (k *HomomorphicCommitmentKey[EK, P, N, C, S]) WitnessOp(first, second *Witness[N], rest ...*Witness[N]) (*Witness[N], error) {
	if first == nil || second == nil {
		return nil, commitments.ErrIsNil.WithMessage("first and second witnesses must not be nil")
	}
	if len(rest) > 0 && sliceutils.Any(rest, func(w *Witness[N]) bool { return w == nil }) {
		return nil, commitments.ErrIsNil.WithMessage("rest witnesses must not contain nil")
	}
	nonce, err := k.encryptionKey.NonceOp(first.Value(), second.Value(), sliceutils.Map(rest, func(w *Witness[N]) N { return w.Value() })...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not perform nonce operation")
	}
	out, err := NewWitness(nonce)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create witness from nonce")
	}
	return out, nil
}

// WitnessOpInv inverts a nonce, giving the witness for the inverse commitment
// (CommitmentOpInv).
func (k *HomomorphicCommitmentKey[EK, P, N, C, S]) WitnessOpInv(w *Witness[N]) (*Witness[N], error) {
	if w == nil {
		return nil, commitments.ErrIsNil.WithMessage("witness must not be nil")
	}
	nonce, err := k.encryptionKey.NonceOpInv(w.Value())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not perform nonce inverse operation")
	}
	out, err := NewWitness(nonce)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create witness from nonce")
	}
	return out, nil
}

// WitnessScalarOp scales a nonce by scalar, matching the witness of a commitment
// scaled by the same scalar (CommitmentScalarOp).
func (k *HomomorphicCommitmentKey[EK, P, N, C, S]) WitnessScalarOp(w *Witness[N], scalar S) (*Witness[N], error) {
	if w == nil || utils.IsNil(scalar) {
		return nil, commitments.ErrIsNil.WithMessage("witness and scalar must not be nil")
	}
	nonce, err := k.encryptionKey.NonceScalarOp(w.Value(), scalar)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not perform nonce scalar operation")
	}
	out, err := NewWitness(nonce)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create witness from nonce")
	}
	return out, nil
}

// MessageOp combines plaintexts with the encryption scheme's plaintext operation;
// a commitment to the result equals the CommitmentOp of the individual commitments.
func (k *HomomorphicCommitmentKey[EK, P, N, C, S]) MessageOp(first, second *Message[P], rest ...*Message[P]) (*Message[P], error) {
	if first == nil || second == nil {
		return nil, commitments.ErrIsNil.WithMessage("first and second messages must not be nil")
	}
	if len(rest) > 0 && sliceutils.Any(rest, func(m *Message[P]) bool { return m == nil }) {
		return nil, commitments.ErrIsNil.WithMessage("rest messages must not contain nil")
	}
	plaintext, err := k.encryptionKey.PlaintextOp(first.Value(), second.Value(), sliceutils.Map(rest, func(m *Message[P]) P { return m.Value() })...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not perform plaintext operation")
	}
	out, err := NewMessage(plaintext)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create message from plaintext")
	}
	return out, nil
}

// MessageOpInv inverts a plaintext, matching CommitmentOpInv on its commitment.
func (k *HomomorphicCommitmentKey[EK, P, N, C, S]) MessageOpInv(m *Message[P]) (*Message[P], error) {
	if m == nil {
		return nil, commitments.ErrIsNil.WithMessage("message must not be nil")
	}
	plaintext, err := k.encryptionKey.PlaintextOpInv(m.Value())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not perform plaintext inverse operation")
	}
	out, err := NewMessage(plaintext)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create message from plaintext")
	}
	return out, nil
}

// MessageScalarOp scales a plaintext by scalar, matching CommitmentScalarOp on its
// commitment.
func (k *HomomorphicCommitmentKey[EK, P, N, C, S]) MessageScalarOp(m *Message[P], scalar S) (*Message[P], error) {
	if m == nil || utils.IsNil(scalar) {
		return nil, commitments.ErrIsNil.WithMessage("message and scalar must not be nil")
	}
	plaintext, err := k.encryptionKey.PlaintextScalarOp(m.Value(), scalar)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not perform plaintext scalar operation")
	}
	out, err := NewMessage(plaintext)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create message from plaintext")
	}
	return out, nil
}

// CommitmentOp combines commitments using the ciphertext homomorphism. The result
// is a commitment to the combined message under the combined nonce.
func (k *HomomorphicCommitmentKey[EK, P, N, C, S]) CommitmentOp(first, second *Commitment[C], rest ...*Commitment[C]) (*Commitment[C], error) {
	if first == nil || second == nil {
		return nil, commitments.ErrIsNil.WithMessage("first and second commitments must not be nil")
	}
	if len(rest) > 0 && sliceutils.Any(rest, func(c *Commitment[C]) bool { return c == nil }) {
		return nil, commitments.ErrIsNil.WithMessage("rest commitments must not contain nil")
	}
	ciphertext, err := k.encryptionKey.CiphertextOp(first.Value(), second.Value(), sliceutils.Map(rest, func(c *Commitment[C]) C { return c.Value() })...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not perform ciphertext operation")
	}
	out, err := NewCommitment(ciphertext)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create commitment from ciphertext")
	}
	return out, nil
}

// CommitmentOpInv returns the homomorphic inverse of a commitment: a commitment to
// the inverted message under the inverted nonce.
func (k *HomomorphicCommitmentKey[EK, P, N, C, S]) CommitmentOpInv(c *Commitment[C]) (*Commitment[C], error) {
	if c == nil {
		return nil, commitments.ErrIsNil.WithMessage("commitment must not be nil")
	}
	ciphertext, err := k.encryptionKey.CiphertextOpInv(c.Value())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not perform ciphertext inverse operation")
	}
	out, err := NewCommitment(ciphertext)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create commitment from ciphertext")
	}
	return out, nil
}

// CommitmentScalarOp scales a commitment by scalar, scaling both the committed
// message and the nonce.
func (k *HomomorphicCommitmentKey[EK, P, N, C, S]) CommitmentScalarOp(c *Commitment[C], scalar S) (*Commitment[C], error) {
	if c == nil || utils.IsNil(scalar) {
		return nil, commitments.ErrIsNil.WithMessage("commitment and scalar must not be nil")
	}
	ciphertext, err := k.encryptionKey.CiphertextScalarOp(c.Value(), scalar)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not perform ciphertext scalar operation")
	}
	out, err := NewCommitment(ciphertext)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create commitment from ciphertext")
	}
	return out, nil
}

// ReRandomise applies the ciphertext re-randomisation with witnessShift, producing
// an unlinkable commitment to the SAME message whose witness is shifted by
// witnessShift. Use a freshly sampled shift for unlinkability.
func (k *HomomorphicCommitmentKey[EK, P, N, C, S]) ReRandomise(c *Commitment[C], witnessShift *Witness[N]) (*Commitment[C], error) {
	if c == nil || witnessShift == nil {
		return nil, commitments.ErrIsNil.WithMessage("commitment and witness shift must not be nil")
	}
	ciphertext, err := k.encryptionKey.ReRandomise(c.Value(), witnessShift.Value())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not perform ciphertext re-randomisation")
	}
	out, err := NewCommitment(ciphertext)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create commitment from ciphertext")
	}
	return out, nil
}

// Shift adds message to the committed value via the ciphertext shift, producing a
// commitment to the shifted message under the SAME witness.
func (k *HomomorphicCommitmentKey[EK, P, N, C, S]) Shift(c *Commitment[C], message *Message[P]) (*Commitment[C], error) {
	if c == nil || message == nil {
		return nil, commitments.ErrIsNil.WithMessage("commitment and message must not be nil")
	}
	ciphertext, err := k.encryptionKey.Shift(c.Value(), message.Value())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not perform ciphertext shift")
	}
	out, err := NewCommitment(ciphertext)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create commitment from ciphertext")
	}
	return out, nil
}

// Equal reports whether two homomorphic keys wrap equal encryption keys, treating
// a nil key as equal only to another nil one.
func (k *HomomorphicCommitmentKey[EK, P, N, C, S]) Equal(other *HomomorphicCommitmentKey[EK, P, N, C, S]) bool {
	if k == nil || other == nil {
		return k == other
	}
	return k.CommitmentKey.Equal(&other.CommitmentKey)
}
