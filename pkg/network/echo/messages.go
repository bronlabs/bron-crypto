package echo

import (
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

// Round1P2P carries the original broadcast payload.
type Round1P2P[B network.Message[BP], BP any] struct {
	Payload []byte `cbor:"payload"`
}

func (r *Round1P2P[B, BP]) Validate(*Participant[B, BP], sharing.ID) error {
	if r == nil {
		return ErrInvalidArgument.WithMessage("missing message")
	}
	return nil
}

// Round2P2P carries echoed payloads from each sender.
type Round2P2P[B network.Message[BP], BP any] struct {
	Echo map[sharing.ID][]byte `cbor:"echo"`
}

func (r *Round2P2P[B, BP]) Validate(*Participant[B, BP], sharing.ID) error {
	if r == nil {
		return ErrInvalidArgument.WithMessage("missing message")
	}
	return nil
}
