package echo

import (
	"crypto/sha3"

	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

func echoHash(payload []byte) [32]byte {
	return sha3.Sum256(payload)
}

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

// Round2P2P carries a SHA3-256 digest of every round 1 payload, keyed by sender.
type Round2P2P[B network.Message[BP], BP any] struct {
	EchoHashes map[sharing.ID][32]byte `cbor:"echoHashes"`
}

func (r *Round2P2P[B, BP]) Validate(*Participant[B, BP], sharing.ID) error {
	if r == nil {
		return ErrInvalidArgument.WithMessage("missing message")
	}
	return nil
}
