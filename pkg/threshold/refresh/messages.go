package refresh

import (
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/hjky"
)

var _ network.Message[types.ThresholdProtocol] = (*Round1Broadcast)(nil)

type Round1Broadcast = hjky.Round1Broadcast
type Round1P2P = hjky.Round1P2P
