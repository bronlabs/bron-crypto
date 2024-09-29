package coordinator

import "github.com/copperexchange/krypton-primitives/pkg/base/types"

type ClientFactory interface {
	// Dial TODO: adjust params when implementing in SDK as part of the integration
	// * add session (for this basic PoC implementation there's only one)
	// * add notification channel (to track nodes in the session)
	Dial(self types.IdentityKey /* , sessionId */) Client /* , chan Notification */
}

type Client interface {
	SendTo(dest types.IdentityKey, payload []byte)
	Recv() (from types.IdentityKey, payload []byte)

	GetIdentityKey() types.IdentityKey
}
