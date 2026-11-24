package ot

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

// SenderOutput holds the sender's pair of messages for each OT of a batch.
// Messages()[i][c] is the c-th message of the i-th OT. Two parameters describe
// a batch, both in bits:
//   - L, the number of OTs, equal to the number of the receiver's choice bits,
//     a positive multiple of 8 enforced by NewSenderOutput and UnmarshalCBOR;
//   - K, the length of every message, fixed by the message type M.
type SenderOutput[M Message] struct {
	messages [][2]M
}

// senderOutputDTO carries the messages as byte strings so that their width
// can be checked on decoding.
type senderOutputDTO struct {
	Messages [][2][]byte `cbor:"messages"`
}

// NewSenderOutput wraps a batch of message pairs, rejecting an empty batch and
// a batch length L that is not a multiple of 8. The slice is retained, not
// copied.
func NewSenderOutput[M Message](messages [][2]M) (*SenderOutput[M], error) {
	if err := validateBatchLength(len(messages)); err != nil {
		return nil, err
	}
	return &SenderOutput[M]{messages: messages}, nil
}

// InferredL returns the number of OTs L in the batch, which equals the number
// of receiver choice bits, or 0 for a zero-value SenderOutput.
func (s *SenderOutput[M]) InferredL() int {
	if s == nil {
		return 0
	}
	return len(s.messages)
}

// Messages returns the message pairs, indexed by OT and then by message.
func (s *SenderOutput[M]) Messages() [][2]M {
	if s == nil {
		return nil
	}
	return s.messages
}

// MarshalCBOR encodes the message pairs.
func (s *SenderOutput[M]) MarshalCBOR() ([]byte, error) {
	if s == nil {
		return nil, ErrInvalidArgument.WithMessage("sender output must not be nil")
	}
	dto := &senderOutputDTO{Messages: make([][2][]byte, len(s.messages))}
	for i := range s.messages {
		dto.Messages[i] = [2][]byte{MessageAsSlice(&s.messages[i][0]), MessageAsSlice(&s.messages[i][1])}
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal sender output")
	}
	return out, nil
}

// UnmarshalCBOR decodes a batch of message pairs, checks the width of every
// message and validates the batch through NewSenderOutput, so that decoded
// data satisfies the same invariants as constructed data. This is a
// deserialisation trust boundary.
func (s *SenderOutput[M]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[senderOutputDTO](data)
	if err != nil {
		return errs.Join(ErrSerialisation, errs.Wrap(err)).WithMessage("failed to unmarshal sender output")
	}
	messages := make([][2]M, len(dto.Messages))
	for i, pair := range dto.Messages {
		for c := range 2 {
			messages[i][c], err = messageFromBytes[M](pair[c])
			if err != nil {
				return errs.Wrap(err).WithMessage("invalid message %d of OT %d in unmarshalled data", c, i)
			}
		}
	}
	out, err := NewSenderOutput(messages)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid sender output in unmarshalled data")
	}
	*s = *out
	return nil
}

// SenderCorrelatedOutput holds the sender's side of a batch of correlated OTs:
// the two messages of the i-th OT are Messages()[i] and Messages()[i] XOR
// Delta(), where Delta() is the single correlation shared by the whole batch. The
// correlation is secret: whoever learns it recovers the second message of every
// OT from the first, so in TinyOT-style use it is the sender's global MAC key.
// The same two parameters as in SenderOutput describe a batch: L, a positive
// multiple of 8 enforced by NewSenderCorrelatedOutput and UnmarshalCBOR, and K,
// the length of every message and of the correlation, fixed by M.
type SenderCorrelatedOutput[M Message] struct {
	messages []M
	delta    M
}

// senderCorrelatedOutputDTO carries the messages and the correlation as byte
// strings so that their width can be checked on decoding.
type senderCorrelatedOutputDTO struct {
	Messages [][]byte `cbor:"messages"`
	Delta    []byte   `cbor:"delta"`
}

// NewSenderCorrelatedOutput wraps a batch of first messages and the correlation,
// rejecting an empty batch and a batch length L that is not a multiple of 8.
// The slice is retained, not copied.
func NewSenderCorrelatedOutput[M Message](messages []M, delta M) (*SenderCorrelatedOutput[M], error) {
	if err := validateBatchLength(len(messages)); err != nil {
		return nil, err
	}
	return &SenderCorrelatedOutput[M]{messages: messages, delta: delta}, nil
}

// InferredL returns the number of OTs L in the batch, which equals the number
// of receiver choice bits, or 0 for a zero-value SenderCorrelatedOutput.
func (s *SenderCorrelatedOutput[M]) InferredL() int {
	if s == nil {
		return 0
	}
	return len(s.messages)
}

// Messages returns the first message of each OT, indexed by OT; the second
// message of OT i is Messages()[i] XOR Delta().
func (s *SenderCorrelatedOutput[M]) Messages() []M {
	if s == nil {
		return nil
	}
	return s.messages
}

// Delta returns the secret correlation shared by every OT of the batch, or the
// zero message for a nil SenderCorrelatedOutput.
func (s *SenderCorrelatedOutput[M]) Delta() M {
	if s == nil {
		var zero M
		return zero
	}
	return s.delta
}

// MarshalCBOR encodes the first messages and the correlation. The encoding
// contains the secret correlation and must be protected accordingly.
func (s *SenderCorrelatedOutput[M]) MarshalCBOR() ([]byte, error) {
	if s == nil {
		return nil, ErrInvalidArgument.WithMessage("sender correlated output must not be nil")
	}
	dto := &senderCorrelatedOutputDTO{Messages: make([][]byte, len(s.messages)), Delta: MessageAsSlice(&s.delta)}
	for i := range s.messages {
		dto.Messages[i] = MessageAsSlice(&s.messages[i])
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal sender correlated output")
	}
	return out, nil
}

// UnmarshalCBOR decodes the first messages and the correlation, checks their
// width and validates them through NewSenderCorrelatedOutput, so that decoded
// data satisfies the same invariants as constructed data. This is a
// deserialisation trust boundary.
func (s *SenderCorrelatedOutput[M]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[senderCorrelatedOutputDTO](data)
	if err != nil {
		return errs.Join(ErrSerialisation, errs.Wrap(err)).WithMessage("failed to unmarshal sender correlated output")
	}
	messages := make([]M, len(dto.Messages))
	for i, raw := range dto.Messages {
		messages[i], err = messageFromBytes[M](raw)
		if err != nil {
			return errs.Wrap(err).WithMessage("invalid message of OT %d in unmarshalled data", i)
		}
	}
	delta, err := messageFromBytes[M](dto.Delta)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid correlation in unmarshalled data")
	}
	out, err := NewSenderCorrelatedOutput(messages, delta)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid sender correlated output in unmarshalled data")
	}
	*s = *out
	return nil
}

// validateBatchLength checks that L is a positive multiple of 8.
func validateBatchLength(count int) error {
	if count == 0 {
		return ErrInvalidArgument.WithMessage("message batch must not be empty")
	}
	if count%8 != 0 {
		return ErrInvalidArgument.WithMessage("message batch length %d is not a multiple of 8", count)
	}
	return nil
}
