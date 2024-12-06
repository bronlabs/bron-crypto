package signing

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	hashcommitments "github.com/copperexchange/krypton-primitives/pkg/commitments/hash"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/bbot"
	mult "github.com/copperexchange/krypton-primitives/pkg/threshold/mult/dkls23"
	zeroSetup "github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/rprzs/setup"
)

var _ network.Message[types.ThresholdSignatureProtocol] = (*Round1P2P)(nil)
var _ network.Message[types.ThresholdSignatureProtocol] = (*Round2P2P)(nil)
var _ network.Message[types.ThresholdSignatureProtocol] = (*Round3Broadcast)(nil)
var _ network.Message[types.ThresholdSignatureProtocol] = (*Round3P2P)(nil)
var _ network.Message[types.ThresholdSignatureProtocol] = (*Round4Broadcast)(nil)
var _ network.Message[types.ThresholdSignatureProtocol] = (*Round4P2P)(nil)

type Round1P2P struct {
	ZeroSampling *zeroSetup.Round1P2P
	BaseOTSender *bbot.Round1P2P

	_ ds.Incomparable
}

type Round2P2P struct {
	ZeroSampling   *zeroSetup.Round2P2P
	BaseOTReceiver *bbot.Round2P2P

	_ ds.Incomparable
}

type Round3Broadcast struct {
	BigR_i curves.Point

	_ ds.Incomparable
}

type Round3P2P struct {
	InstanceKeyCommitment *hashcommitments.Commitment
	MultiplicationOutput  *mult.Round1Output

	_ ds.Incomparable
}

type Round4Broadcast struct {
	Pk_i curves.Point

	_ ds.Incomparable
}

type Round4P2P struct {
	Multiplication     *mult.Round2Output
	GammaU_ij          curves.Point
	GammaV_ij          curves.Point
	Psi_ij             curves.Scalar
	InstanceKeyOpening *hashcommitments.Opening

	_ ds.Incomparable
}

func (r *Round1P2P) Validate(protocol types.ThresholdSignatureProtocol) error {
	if r.ZeroSampling == nil {
		return errs.NewIsNil("zero sampling message")
	}
	if r.BaseOTSender == nil {
		return errs.NewIsNil("base ot sender message")
	}
	return nil
}

func (r *Round2P2P) Validate(protocol types.ThresholdSignatureProtocol) error {
	if r.ZeroSampling == nil {
		return errs.NewIsNil("zero sampling message")
	}
	if r.BaseOTReceiver == nil {
		return errs.NewIsNil("base ot receiver message")
	}
	return nil
}

func (r1b *Round3Broadcast) Validate(protocol types.ThresholdSignatureProtocol) error {
	if r1b.BigR_i == nil {
		return errs.NewIsNil("BigR_i")
	}
	if r1b.BigR_i.Curve() != protocol.Curve() {
		return errs.NewCurve("BigR_i curve %s does not match protocol curve %s", r1b.BigR_i.Curve(), protocol.Curve())
	}
	if r1b.BigR_i.IsAdditiveIdentity() {
		return errs.NewIsIdentity("BigR_i")
	}
	return nil
}

func (r1p2p *Round3P2P) Validate(protocol types.ThresholdSignatureProtocol) error {
	if r1p2p.InstanceKeyCommitment == nil {
		return errs.NewIsNil("InstanceKeyCommitment")
	}
	if r1p2p.MultiplicationOutput == nil {
		return errs.NewIsNil("MultiplicationOutput")
	}
	return nil
}

func (r2b *Round4Broadcast) Validate(protocol types.ThresholdSignatureProtocol) error {
	if r2b.Pk_i == nil {
		return errs.NewIsNil("Pk_i")
	}
	if r2b.Pk_i.Curve() != protocol.Curve() {
		return errs.NewCurve("Pk_i curve %s does not match protocol curve %s", r2b.Pk_i.Curve(), protocol.Curve())
	}
	if r2b.Pk_i.IsAdditiveIdentity() {
		return errs.NewIsIdentity("Pk_i")
	}
	return nil
}

func (r2p2p *Round4P2P) Validate(protocol types.ThresholdSignatureProtocol) error {
	if r2p2p.Multiplication == nil {
		return errs.NewIsNil("Multiplication")
	}
	if r2p2p.GammaU_ij == nil {
		return errs.NewIsNil("GammaU_ij")
	}
	if r2p2p.GammaV_ij == nil {
		return errs.NewIsNil("GammaV_ij")
	}
	if !curveutils.AllPointsOfSameCurve(protocol.Curve(), r2p2p.GammaU_ij, r2p2p.GammaV_ij) {
		return errs.NewCurve("GammaU_ij and/or GammaV_ij have different curves (expected %s, got %s & %s)",
			protocol.Curve().Name(), r2p2p.GammaU_ij.Curve().Name(), r2p2p.GammaV_ij.Curve().Name())
	}
	if r2p2p.Psi_ij == nil {
		return errs.NewIsNil("Psi_ij")
	}
	if r2p2p.Psi_ij.ScalarField().Curve() != protocol.Curve() {
		return errs.NewCurve("Psi_ij curve %s does not match protocol curve %s", r2p2p.Psi_ij.ScalarField().Curve(), protocol.Curve())
	}
	if r2p2p.Psi_ij.IsZero() {
		return errs.NewIsZero("Psi_ij")
	}
	if err := r2p2p.InstanceKeyOpening.Validate(); err != nil {
		return errs.WrapValidation(err, "could not validate opening")
	}
	return nil
}
