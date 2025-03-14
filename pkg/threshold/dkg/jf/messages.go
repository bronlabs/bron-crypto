package jf

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
)

var _ network.Message[types.ThresholdProtocol] = (*Round1Broadcast)(nil)
var _ network.Message[types.ThresholdProtocol] = (*Round1P2P)(nil)
var _ network.Message[types.ThresholdProtocol] = (*Round2Broadcast)(nil)

type Round1Broadcast struct {
	BlindedCommitments []curves.Point

	_ ds.Incomparable
}

type Round1P2P struct {
	X_ij      curves.Scalar
	XPrime_ij curves.Scalar

	_ ds.Incomparable
}

type Round2Broadcast struct {
	Ci               []curves.Point
	CommitmentsProof compiler.NIZKPoKProof

	_ ds.Incomparable
}

func (r1b *Round1Broadcast) Validate(protocol types.ThresholdProtocol) error {
	if len(r1b.BlindedCommitments) == 0 {
		return errs.NewIsNil("blinded commitments is empty")
	}
	if len(r1b.BlindedCommitments) != int(protocol.Threshold()) {
		return errs.NewLength("len(blindedCommitments) == %d != t == %d", len(r1b.BlindedCommitments), protocol.Threshold())
	}
	for i, commitment := range r1b.BlindedCommitments {
		if commitment == nil {
			return errs.NewIsNil("blindedCommitments[%d]", i)
		}
		if commitment.Curve() != protocol.Curve() {
			return errs.NewCurve("blindedCommitments[%d] curve %s is not protocol curve %s", i, commitment.Curve().Name(), protocol.Curve().Name())
		}
		if commitment.IsAdditiveIdentity() {
			return errs.NewIsZero("blindedCommitments[%d] is identity", i)
		}
	}
	return nil
}

func (r1p2p *Round1P2P) Validate(protocol types.ThresholdProtocol) error {
	if r1p2p.X_ij == nil {
		return errs.NewIsNil("x_ij")
	}
	if r1p2p.X_ij.ScalarField().Curve() != protocol.Curve() {
		return errs.NewCurve("x_ij curve %s is not protocol curve %s", r1p2p.X_ij.ScalarField().Curve().Name(), protocol.Curve().Name())
	}
	if r1p2p.X_ij.IsZero() {
		return errs.NewIsZero("x_ij is zero")
	}
	if r1p2p.XPrime_ij == nil {
		return errs.NewIsNil("xPrime_ij")
	}
	if r1p2p.XPrime_ij.ScalarField().Curve() != protocol.Curve() {
		return errs.NewCurve("xPrime_ij curve %s is not protocol curve %s", r1p2p.XPrime_ij.ScalarField().Curve().Name(), protocol.Curve().Name())
	}
	if r1p2p.XPrime_ij.IsZero() {
		return errs.NewIsZero("xPrime_ij is zero")
	}
	return nil
}

func (r2b *Round2Broadcast) Validate(protocol types.ThresholdProtocol) error {
	if len(r2b.Ci) == 0 {
		return errs.NewSize("commitments is empty")
	}
	if len(r2b.Ci) != int(protocol.Threshold()) {
		return errs.NewLength("len(senderCommitmentVector) == %d != t == %d", len(r2b.Ci), protocol.Threshold())
	}
	for i, commitment := range r2b.Ci {
		if commitment == nil {
			return errs.NewIsNil("commitments[%d]", i)
		}
		if commitment.Curve() != protocol.Curve() {
			return errs.NewCurve("commitments[%d] curve %s is not protocol curve %s", i, commitment.Curve().Name(), protocol.Curve().Name())
		}
		if commitment.IsAdditiveIdentity() {
			return errs.NewIsZero("commitments[%d] is identity", i)
		}
	}
	if r2b.CommitmentsProof == nil {
		return errs.NewIsNil("commitments proof")
	}
	return nil
}
