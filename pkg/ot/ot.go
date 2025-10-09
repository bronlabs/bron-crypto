package ot

import "github.com/bronlabs/bron-crypto/pkg/base/errs"

type Suite interface {
	Xi() int
	L() int
}

type DefaultSuite struct {
	xi int
	l  int
}

func NewDefaultSuite(xi, l int) (*DefaultSuite, error) {
	if xi <= 0 || l <= 0 {
		return nil, errs.NewValidation("invalid args")
	}
	return &DefaultSuite{xi, l}, nil
}

func (s *DefaultSuite) Xi() int {
	return s.xi
}

func (s *DefaultSuite) L() int {
	return s.l
}

type SenderOutput[D any] struct {
	Messages [][2][]D `cbor:"messages"`
}

func (so *SenderOutput[D]) InferredXi() int {
	return len(so.Messages)
}

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

type ReceiverOutput[D any] struct {
	Choices  []byte `cbor:"choices"`
	Messages [][]D  `cbor:"messages"`
}

func (ro *ReceiverOutput[D]) InferredXi() int {
	xi := len(ro.Messages)
	if len(ro.Choices)*8 != len(ro.Messages) {
		return 0
	}

	return xi
}

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
