package recovery

import (
	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

var (
	_ network.Message[types.ThresholdProtocol] = (*Round1P2P)(nil)
)

type Round1P2P struct {
	N1 *saferith.Modulus
	N2 *saferith.Modulus
	E  uint64

	D1 *saferith.Int
	D2 *saferith.Int
}

func (m *Round1P2P) Validate(_ types.ThresholdProtocol) error {
	if m.N1 == nil || m.N2 == nil || m.D1 == nil || m.D2 == nil {
		return errs.NewValidation("invalid message")
	}

	return nil
}
