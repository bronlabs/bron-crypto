package auth

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type ClientFactory interface {
	Dial(self types.AuthKey) Client
}

type Client interface {
	SendTo(to types.IdentityKey, payload []byte)
	Recv() (from types.IdentityKey, payload []byte)
	GetAuthKey() types.AuthKey
}

func init() {
	curveutils.RegisterCurvesForGob()
}
