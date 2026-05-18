package indcpacom

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

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

type HomomorphicCommitmentKey[
	EK encryption.HomomorphicEncryptionKey[EK, P, N, C, S],
	P encryption.Plaintext,
	N encryption.Nonce,
	C encryption.Ciphertext[C],
	S any,
] struct {
	CommitmentKey[EK, P, N, C]
}

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

func (k *HomomorphicCommitmentKey[EK, P, N, C, S]) Equal(other *HomomorphicCommitmentKey[EK, P, N, C, S]) bool {
	if k == nil || other == nil {
		return k == other
	}
	return k.CommitmentKey.Equal(&other.CommitmentKey)
}
