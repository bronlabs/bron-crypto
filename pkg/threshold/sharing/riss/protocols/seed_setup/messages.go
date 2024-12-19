package riss_seed_setup

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/riss"
)

var (
	_ network.Message[types.ThresholdProtocol] = (*Round1P2P)(nil)
)

type Round1P2P struct {
	Seeds map[riss.SharingIdSet][64]byte
}

func (*Round1P2P) Validate(protocol types.ThresholdProtocol) error {
	return nil
}
