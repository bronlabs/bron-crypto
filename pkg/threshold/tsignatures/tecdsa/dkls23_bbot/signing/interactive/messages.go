package interactive

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/network"
	bbotMul "github.com/bronlabs/bron-crypto/pkg/threshold/mult/dkls23_bbot"
	zeroSetup "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/rprzs/setup"
)

var (
	_ network.Message[types.ThresholdSignatureProtocol] = (*Round1Broadcast)(nil)
	_ network.Message[types.ThresholdSignatureProtocol] = (*Round1P2P)(nil)
	_ network.Message[types.ThresholdSignatureProtocol] = (*Round2Broadcast)(nil)
	_ network.Message[types.ThresholdSignatureProtocol] = (*Round2P2P)(nil)
	_ network.Message[types.ThresholdSignatureProtocol] = (*Round3Broadcast)(nil)
	_ network.Message[types.ThresholdSignatureProtocol] = (*Round3P2P)(nil)
)

type Round1Broadcast struct {
	BigRCommitment hash_comm.Commitment
}

func (m *Round1Broadcast) Validate(protocol types.ThresholdSignatureProtocol) error {
	if m == nil {
		return errs.NewValidation("invalid message")
	}
	return nil
}

type Round1P2P struct {
	ZeroSetupR1 *zeroSetup.Round1P2P
	MulR1       *bbotMul.Round1P2P
}

func (m *Round1P2P) Validate(protocol types.ThresholdSignatureProtocol) error {
	if m == nil || m.ZeroSetupR1 == nil || m.MulR1 == nil {
		return errs.NewValidation("invalid message")
	}
	return nil
}

type Round2Broadcast struct {
	BigR        curves.Point
	BigRWitness hash_comm.Witness
}

func (m *Round2Broadcast) Validate(protocol types.ThresholdSignatureProtocol) error {
	if m == nil || m.BigR == nil || m.BigR.Curve().Name() != protocol.Curve().Name() || m.BigR.IsAdditiveIdentity() {
		return errs.NewValidation("invalid message")
	}
	return nil
}

type Round2P2P struct {
	ZeroSetupR2 *zeroSetup.Round2P2P
	MulR2       *bbotMul.Round2P2P
}

func (m *Round2P2P) Validate(_ types.ThresholdSignatureProtocol) error {
	if m == nil || m.ZeroSetupR2 == nil || m.MulR2 == nil {
		return errs.NewValidation("invalid message")
	}
	return nil
}

type Round3Broadcast struct {
	Pk curves.Point
}

func (m *Round3Broadcast) Validate(protocol types.ThresholdSignatureProtocol) error {
	if m == nil || m.Pk == nil || m.Pk.Curve().Name() != protocol.Curve().Name() || m.Pk.IsAdditiveIdentity() {
		return errs.NewValidation("invalid message")
	}
	return nil
}

type Round3P2P struct {
	MulR3 *bbotMul.Round3P2P

	GammaU curves.Point
	GammaV curves.Point
	Psi    curves.Scalar
}

func (m *Round3P2P) Validate(protocol types.ThresholdSignatureProtocol) error {
	if m == nil || m.MulR3 == nil {
		return errs.NewValidation("invalid message")
	}
	if m.Psi == nil || m.Psi.ScalarField().Curve().Name() != protocol.Curve().Name() ||
		m.GammaU == nil || m.GammaU.Curve().Name() != protocol.Curve().Name() || m.GammaU.IsAdditiveIdentity() ||
		m.GammaV == nil || m.GammaU.Curve().Name() != protocol.Curve().Name() || m.GammaV.IsAdditiveIdentity() {

		return errs.NewValidation("invalid message")
	}
	return nil
}
