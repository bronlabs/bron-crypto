package network

import (
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// SID is a 32-byte session identifier derived from hashed inputs.
type SID [32]byte

// Message represents any network payload.
type Message[P any] interface {
	Validate(receiver P, senderID sharing.ID) error
}
