package hjky

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/network"
	feldman_vss "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
)

var (
	_ network.Message[types.ThresholdProtocol] = (*Round1Broadcast)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round1P2P)(nil)
)

type Round1Broadcast struct {
	FeldmanVerification []curves.Point
}

func (m *Round1Broadcast) Validate(protocol types.ThresholdProtocol) error {
	if len(m.FeldmanVerification) != int(protocol.Threshold()) {
		return errs.NewValidation("feldman length mismatch")
	}

	return nil
}

type Round1P2P struct {
	FeldmanShare *feldman_vss.Share
}

func (m *Round1P2P) Validate(protocol types.ThresholdProtocol) error {
	if m.FeldmanShare == nil || m.FeldmanShare.SharingId() < 1 || uint(m.FeldmanShare.SharingId()) > protocol.TotalParties() {
		return errs.NewValidation("feldman sharing id mismatch")
	}

	return nil
}
