package rb

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type Auth interface {
	Send(to types.IdentityKey, message []byte) error
	Receive() (from types.IdentityKey, message []byte, err error)
	GetCoordinator() Coordinator
}
