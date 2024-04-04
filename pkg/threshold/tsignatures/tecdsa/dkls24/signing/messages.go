package signing

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/mult"
)

var _ network.Message[types.ThresholdSignatureProtocol] = (*Round1Broadcast)(nil)
var _ network.Message[types.ThresholdSignatureProtocol] = (*Round1P2P)(nil)
var _ network.Message[types.ThresholdSignatureProtocol] = (*Round2Broadcast)(nil)
var _ network.Message[types.ThresholdSignatureProtocol] = (*Round2P2P)(nil)

type Round1Broadcast struct {
	BigR_i curves.Point

	_ ds.Incomparable
}

type Round1P2P struct {
	InstanceKeyCommitment commitments.Commitment
	MultiplicationOutput  *mult.Round1Output

	_ ds.Incomparable
}

type Round2Broadcast struct {
	Pk_i curves.Point

	_ ds.Incomparable
}

type Round2P2P struct {
	Multiplication     *mult.Round2Output
	GammaU_ij          curves.Point
	GammaV_ij          curves.Point
	Psi_ij             curves.Scalar
	InstanceKeyWitness commitments.Witness

	_ ds.Incomparable
}

func (r1b *Round1Broadcast) Validate(protocol types.ThresholdSignatureProtocol) error {
	if r1b.BigR_i == nil {
		return errs.NewIsNil("BigR_i")
	}
	if r1b.BigR_i.Curve() != protocol.Curve() {
		return errs.NewCurve("BigR_i curve %s does not match protocol curve %s", r1b.BigR_i.Curve(), protocol.Curve())
	}
	if r1b.BigR_i.IsIdentity() {
		return errs.NewIsIdentity("BigR_i")
	}
	return nil
}

func (r1p2p *Round1P2P) Validate(protocol types.ThresholdSignatureProtocol) error {
	if r1p2p.InstanceKeyCommitment == nil {
		return errs.NewIsNil("InstanceKeyCommitment")
	}
	if r1p2p.MultiplicationOutput == nil {
		return errs.NewIsNil("MultiplicationOutput")
	}
	return nil
}

func (r2b *Round2Broadcast) Validate(protocol types.ThresholdSignatureProtocol) error {
	if r2b.Pk_i == nil {
		return errs.NewIsNil("Pk_i")
	}
	if r2b.Pk_i.Curve() != protocol.Curve() {
		return errs.NewCurve("Pk_i curve %s does not match protocol curve %s", r2b.Pk_i.Curve(), protocol.Curve())
	}
	if r2b.Pk_i.IsIdentity() {
		return errs.NewIsIdentity("Pk_i")
	}
	return nil
}

func (r2p2p *Round2P2P) Validate(protocol types.ThresholdSignatureProtocol) error {
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
	if r2p2p.InstanceKeyWitness == nil {
		return errs.NewIsNil("InstanceKeyWitness")
	}
	return nil
}
