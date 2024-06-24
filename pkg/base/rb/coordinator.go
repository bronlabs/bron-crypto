package rb

import "github.com/copperexchange/krypton-primitives/pkg/base/types"

// Coordinator uses p2p only current, so I don't bother to put broadcast for now
type Coordinator interface {
	Send(to types.IdentityKey, message []byte) error
	Receive() (from types.IdentityKey, message []byte, err error)
	GetAuthKey() types.AuthKey
	GetParticipants() []types.IdentityKey
}
