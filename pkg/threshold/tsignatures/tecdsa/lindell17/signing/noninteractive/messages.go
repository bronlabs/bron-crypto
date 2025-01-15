package noninteractive_signing

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	hashcommitments "github.com/bronlabs/krypton-primitives/pkg/commitments/hash"
	"github.com/bronlabs/krypton-primitives/pkg/network"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler"
)

var _ network.Message[types.ThresholdProtocol] = (*Round1Broadcast)(nil)
var _ network.Message[types.ThresholdProtocol] = (*Round2Broadcast)(nil)

type Round1Broadcast struct {
	BigRCommitment *hashcommitments.Commitment

	_ ds.Incomparable
}

type Round2Broadcast struct {
	BigR        curves.Point
	BigRProof   compiler.NIZKPoKProof
	BigROpening *hashcommitments.Opening

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
	if r2b.BigR.IsAdditiveIdentity() {
		return errs.NewIsIdentity("bigR")
	}
	if r2b.BigRProof == nil {
		return errs.NewIsNil("bigRProof")
	}
	if err := r2b.BigROpening.Validate(); err != nil {
		return errs.WrapValidation(err, "could not validate opening")
	}
	return nil
}
