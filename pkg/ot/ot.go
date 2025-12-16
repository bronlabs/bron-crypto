package ot

import "github.com/bronlabs/bron-crypto/pkg/base/errs"

// Suite captures batch and block sizes for an OT instantiation.
type Suite interface {
	Xi() int
	L() int
}

// DefaultSuite implements Suite with fixed parameters.
type DefaultSuite struct {
	xi int
	l  int
}

// NewDefaultSuite constructs a suite with the given batch size xi and message block length l.
func NewDefaultSuite(xi, l int) (*DefaultSuite, error) {
	if xi <= 0 || l <= 0 {
		return nil, errs.NewValidation("invalid args")
	}
	return &DefaultSuite{xi, l}, nil
}

// Xi returns the batch size (number of parallel OTs).
func (s *DefaultSuite) Xi() int {
	return s.xi
}

// L returns the message block length.
func (s *DefaultSuite) L() int {
	return s.l
}

// SenderOutput holds the sender's pair of messages for each OT and block index.
type SenderOutput[D any] struct {
	Messages [][2][]D `cbor:"messages"`
}

// InferredXi infers xi from the message count, or returns 0 if inconsistent.
func (so *SenderOutput[D]) InferredXi() int {
	return len(so.Messages)
}

// InferredL infers l from the first entry and validates consistency across all entries.
func (so *SenderOutput[D]) InferredL() int {
	if len(so.Messages) == 0 {
		return 0
	}

	l := len(so.Messages[0][0])
	for _, messages := range so.Messages {
		l0 := len(messages[0])
		l1 := len(messages[1])
		if l0 != l {
			return 0
		}
		if l1 != l {
			return 0
		}
	}

	return l
}

// ReceiverOutput holds the receiver's choice bits and selected messages.
type ReceiverOutput[D any] struct {
	Choices  []byte `cbor:"choices"`
	Messages [][]D  `cbor:"messages"`
}

// InferredXi infers xi from choice bits and message count, returning 0 on mismatch.
func (ro *ReceiverOutput[D]) InferredXi() int {
	xi := len(ro.Messages)
	if len(ro.Choices)*8 != len(ro.Messages) {
		return 0
	}

	return xi
}

// InferredL infers l from the first row and validates consistency across all entries.
func (ro *ReceiverOutput[D]) InferredL() int {
	if len(ro.Messages) == 0 {
		return 0
	}
	l := len(ro.Messages[0])
	for _, messages := range ro.Messages {
		if len(messages) != l {
			return 0
		}
	}
	return l
}
