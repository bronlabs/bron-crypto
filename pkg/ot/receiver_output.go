package ot

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

// ReceiverOutput holds the receiver's packed choice bits and, for each OT of a
// batch, the message it chose: Messages()[i] is the sender's message selected
// by choice bit i. The same two parameters as in SenderOutput describe a batch:
// L, the number of OTs and of choice bits, a positive multiple of 8 enforced by
// NewReceiverOutput and UnmarshalCBOR, and K, the message length fixed by M.
type ReceiverOutput[M Message] struct {
	choices  Choices
	messages []M
}

// receiverOutputDTO carries the messages as byte strings so that their width
// can be checked on decoding.
type receiverOutputDTO struct {
	Choices  Choices  `cbor:"choices"`
	Messages [][]byte `cbor:"messages"`
}

// NewReceiverOutput wraps packed choice bits and the chosen messages, rejecting
// an empty batch, a batch length L that is not a multiple of 8 and choices that
// do not hold exactly L bits. The slices are retained, not copied.
func NewReceiverOutput[M Message](choices Choices, messages []M) (*ReceiverOutput[M], error) {
	count := len(messages)
	if err := validateBatchLength(count); err != nil {
		return nil, err
	}
	if choices.BitLen() != count {
		return nil, ErrInvalidArgument.WithMessage("choices holds %d bits, expected %d for %d OTs", choices.BitLen(), count, count)
	}
	return &ReceiverOutput[M]{choices: choices, messages: messages}, nil
}

// InferredL returns the number of OTs L in the batch, which equals the number
// of choice bits, or 0 for a zero-value ReceiverOutput.
func (r *ReceiverOutput[M]) InferredL() int {
	if r == nil {
		return 0
	}
	return len(r.messages)
}

// Choices returns the L packed choice bits.
func (r *ReceiverOutput[M]) Choices() Choices {
	if r == nil {
		return nil
	}
	return r.choices
}

// Messages returns the chosen messages, indexed by OT.
func (r *ReceiverOutput[M]) Messages() []M {
	if r == nil {
		return nil
	}
	return r.messages
}

// MarshalCBOR encodes the choice bits and the chosen messages.
func (r *ReceiverOutput[M]) MarshalCBOR() ([]byte, error) {
	if r == nil {
		return nil, ErrInvalidArgument.WithMessage("receiver output must not be nil")
	}
	dto := &receiverOutputDTO{Choices: r.choices, Messages: make([][]byte, len(r.messages))}
	for i := range r.messages {
		dto.Messages[i] = MessageAsSlice(&r.messages[i])
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal receiver output")
	}
	return out, nil
}

// UnmarshalCBOR decodes choice bits and messages, checks the width of every
// message and validates them through NewReceiverOutput, so that decoded data
// satisfies the same invariants as constructed data. This is a deserialisation
// trust boundary.
func (r *ReceiverOutput[M]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[receiverOutputDTO](data)
	if err != nil {
		return errs.Join(ErrSerialisation, errs.Wrap(err)).WithMessage("failed to unmarshal receiver output")
	}
	messages := make([]M, len(dto.Messages))
	for i, raw := range dto.Messages {
		messages[i], err = messageFromBytes[M](raw)
		if err != nil {
			return errs.Wrap(err).WithMessage("invalid message of OT %d in unmarshalled data", i)
		}
	}
	out, err := NewReceiverOutput(dto.Choices, messages)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid receiver output in unmarshalled data")
	}
	*r = *out
	return nil
}
