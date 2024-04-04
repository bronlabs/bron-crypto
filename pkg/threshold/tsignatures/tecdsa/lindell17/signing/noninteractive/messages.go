package noninteractive_signing

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
)

var _ network.Message[types.ThresholdProtocol] = (*Round1Broadcast)(nil)
var _ network.Message[types.ThresholdProtocol] = (*Round2Broadcast)(nil)

type Round1Broadcast struct {
	BigRCommitment commitments.Commitment

	_ ds.Incomparable
}

type Round2Broadcast struct {
	BigR        curves.Point
	BigRProof   compiler.NIZKPoKProof
	BigRWitness commitments.Witness

	_ ds.Incomparable
}

func (r1b *Round1Broadcast) Validate(protocol types.ThresholdProtocol) error {
	if r1b.BigRCommitment == nil {
		return errs.NewIsNil("bigRCommitment")
	}
	return nil
}

func (r2b *Round2Broadcast) Validate(protocol types.ThresholdProtocol) error {
	if r2b.BigR == nil {
		return errs.NewIsNil("bigR")
	}
	if r2b.BigR.Curve() != protocol.Curve() {
		return errs.NewCurve("bigR curve %s does not match protocol curve %s", r2b.BigR.Curve(), protocol.Curve())
	}
	if r2b.BigR.IsIdentity() {
		return errs.NewIsIdentity("bigR")
	}
	if r2b.BigRProof == nil {
		return errs.NewIsNil("bigRProof")
	}
	if r2b.BigRWitness == nil {
		return errs.NewIsNil("bigRWitness")
	}
	return nil
}
