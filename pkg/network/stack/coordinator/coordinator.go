package coordinator

import "github.com/copperexchange/krypton-primitives/pkg/base/types"

type ClientFactory interface {
	// Dial TODO:
	// * add notification channel (to track nodes in the session)
	Dial(coordinatorURL string, sessionID []byte, identity types.IdentityKey, participants []types.IdentityKey) Client
}

type Client interface {
	SendTo(to types.IdentityKey, payload []byte)
	Recv() (from types.IdentityKey, payload []byte)

	GetIdentityKey() types.IdentityKey
}
