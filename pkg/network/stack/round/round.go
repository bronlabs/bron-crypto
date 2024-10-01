package round

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type ClientFactory interface {
	Dial(self types.AuthKey, protocol types.Protocol) Client
}

type Client interface {
	Send(roundId string, b []byte, u ds.Map[types.IdentityKey, []byte])
	Receive(roundId string, fromB []types.IdentityKey, fromU []types.IdentityKey) (b ds.Map[types.IdentityKey, []byte], u ds.Map[types.IdentityKey, []byte])
	GetAuthKey() types.AuthKey
}
