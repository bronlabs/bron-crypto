package riss_batch_mul

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"math/big"
)

var (
	_ network.Message[types.ThresholdProtocol] = (*Round1P2P)(nil)
)

type Round1P2P struct {
	V []*big.Int
}

func (m *Round1P2P) Validate(types.ThresholdProtocol) error {
	if len(m.V) == 0 {
		return errs.NewValidation("v is empty")
	}

	return nil
}
