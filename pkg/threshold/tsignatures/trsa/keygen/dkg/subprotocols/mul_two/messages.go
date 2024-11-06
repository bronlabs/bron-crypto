package mul_two

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
)

var (
	_ network.Message[types.ThresholdProtocol] = (*Round1P2P)(nil)
)

type Round1P2P struct {
	Share *replicated.IntShare
}

func (m *Round1P2P) Validate(types.ThresholdProtocol) error {
	return nil
}
