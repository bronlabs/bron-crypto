package recovery

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/network"
	feldman_vss "github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/feldman"
)

var (
	_ network.Message[types.ThresholdProtocol] = (*Round1Broadcast)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round2P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round3Broadcast)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round3P2P)(nil)
)

type Round1Broadcast struct {
	FeldmanVerification []curves.Point
}

func (m *Round1Broadcast) Validate(protocol types.ThresholdProtocol) error {
	if len(m.FeldmanVerification) != int(protocol.Threshold()) {
		return errs.NewValidation("invalid message")
	}

	return nil
}

type Round2P2P struct {
	FeldmanShare *feldman_vss.Share
}

func (m *Round2P2P) Validate(protocol types.ThresholdProtocol) error {
	if m.FeldmanShare == nil || m.FeldmanShare.SharingId() < 1 || uint(m.FeldmanShare.SharingId()) > protocol.TotalParties() {
		return errs.NewValidation("invalid message")
	}

	return nil
}

type Round3Broadcast struct {
	FeldmanVerification []curves.Point
}

func (m *Round3Broadcast) Validate(protocol types.ThresholdProtocol) error {
	if len(m.FeldmanVerification) != int(protocol.Threshold()) {
		return errs.NewValidation("invalid message")
	}

	return nil
}

type Round3P2P struct {
	BlindFeldmanShare *feldman_vss.Share
}

func (m *Round3P2P) Validate(protocol types.ThresholdProtocol) error {
	if m.BlindFeldmanShare == nil || m.BlindFeldmanShare.SharingId() < 1 || uint(m.BlindFeldmanShare.SharingId()) > protocol.TotalParties() {
		return errs.NewValidation("invalid message")
	}

	return nil
}
