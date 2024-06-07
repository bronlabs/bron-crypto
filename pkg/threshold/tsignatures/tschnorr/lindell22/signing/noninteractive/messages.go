package noninteractive_signing

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	hashcommitments "github.com/copperexchange/krypton-primitives/pkg/commitments/hash"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/rprzs/setup"
)

var _ network.Message[types.ThresholdProtocol] = (*Round1Broadcast)(nil)
var _ network.Message[types.ThresholdProtocol] = (*Round2Broadcast)(nil)

type Round1Broadcast struct {
	BigRCommitment *hashcommitments.Commitment

	_ ds.Incomparable
}

type Round1P2P = setup.Round1P2P

type Round2Broadcast struct {
	BigR1       curves.Point
	BigR2       curves.Point
	BigROpening *hashcommitments.Opening
	BigR1Proof  compiler.NIZKPoKProof
	BigR2Proof  compiler.NIZKPoKProof

	_ ds.Incomparable
}

type Round2P2P = setup.Round2P2P

func (r1b *Round1Broadcast) Validate(protocol types.ThresholdProtocol) error {
	if err := r1b.BigRCommitment.Validate(); err != nil {
		return errs.WrapValidation(err, "commitment validation failed")
	}
	return nil
}

func (r2b *Round2Broadcast) Validate(protocol types.ThresholdProtocol) error {
	if r2b.BigR1 == nil {
		return errs.NewIsNil("big r1")
	}
	if r2b.BigR1.Curve() != protocol.Curve() {
		return errs.NewCurve("big r1 curve %s does not match protocol curve %s", r2b.BigR1.Curve(), protocol.Curve())
	}
	if r2b.BigR1.IsAdditiveIdentity() {
		return errs.NewIsIdentity("big r1")
	}
	if r2b.BigR2 == nil {
		return errs.NewIsNil("big r2")
	}
	if r2b.BigR2.Curve() != protocol.Curve() {
		return errs.NewCurve("big r2 curve %s does not match protocol curve %s", r2b.BigR2.Curve(), protocol.Curve())
	}
	if r2b.BigR2.IsAdditiveIdentity() {
		return errs.NewIsIdentity("big r2")
	}
	if err := r2b.BigROpening.Validate(); err != nil {
		return errs.WrapValidation(err, "could not validate opening")
	}
	if r2b.BigR1Proof == nil {
		return errs.NewIsNil("big r1 proof")
	}
	if r2b.BigR2Proof == nil {
		return errs.NewIsNil("big r2 proof")
	}
	return nil
}
