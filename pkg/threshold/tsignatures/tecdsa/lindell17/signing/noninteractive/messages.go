package noninteractive_signing

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	hashcommitments "github.com/copperexchange/krypton-primitives/pkg/vector_commitments/hash"
)

var _ network.Message[types.ThresholdProtocol] = (*Round1Broadcast)(nil)
var _ network.Message[types.ThresholdProtocol] = (*Round2Broadcast)(nil)

type Round1Broadcast struct {
	BigRCommitment hashcommitments.Commitment

	_ ds.Incomparable
}

type Round2Broadcast struct {
	BigR        curves.Point
	BigRProof   compiler.NIZKPoKProof
	BigROpening hashcommitments.Opening

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

	return nil
}
