package gennaro

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	pedersen_comm "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/network"
	pedersen_vss "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/pedersen"
)

var _ network.Message[types.ThresholdProtocol] = (*Round1Broadcast)(nil)
var _ network.Message[types.ThresholdProtocol] = (*Round2P2P)(nil)
var _ network.Message[types.ThresholdProtocol] = (*Round2Broadcast)(nil)

type Round1Broadcast struct {
	PedersenVerification []pedersen_comm.Commitment
}

func (m *Round1Broadcast) Validate(protocol types.ThresholdProtocol) error {
	if len(m.PedersenVerification) != int(protocol.Threshold()) {
		return errs.NewValidation("invalid vector length")
	}

	return nil
}

type Round2P2P struct {
	PedersenShare *pedersen_vss.Share
}

func (m *Round2P2P) Validate(protocol types.ThresholdProtocol) error {
	if m.PedersenShare == nil || m.PedersenShare.SharingId() < 1 || uint(m.PedersenShare.SharingId()) > protocol.TotalParties() {
		return errs.NewValidation("invalid pedersen share")
	}

	return nil
}

type Round2Broadcast struct {
	FeldmanVerification []curves.Point
}

func (m *Round2Broadcast) Validate(protocol types.ThresholdProtocol) error {
	if len(m.FeldmanVerification) != int(protocol.Threshold()) {
		return errs.NewValidation("invalid vector length")
	}

	return nil
}
