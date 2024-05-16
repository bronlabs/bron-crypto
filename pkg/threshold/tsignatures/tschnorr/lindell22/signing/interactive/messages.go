package interactive_signing

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/rprzs/setup"
	"github.com/copperexchange/krypton-primitives/pkg/veccomm/hashveccomm"
)

var _ network.Message[types.ThresholdSignatureProtocol] = (*Round1Broadcast)(nil)
var _ network.Message[types.ThresholdSignatureProtocol] = (*Round2Broadcast)(nil)

type Round1Broadcast struct {
	BigRCommitment *hashveccomm.VectorCommitment

	_ ds.Incomparable
}

type Round1P2P = setup.Round1P2P

type Round2Broadcast struct {
	BigRProof   compiler.NIZKPoKProof
	BigR        curves.Point
	BigROpening *hashveccomm.Opening

	_ ds.Incomparable
}

type Round2P2P = setup.Round2P2P

func (r1b *Round1Broadcast) Validate(protocol types.ThresholdSignatureProtocol) error {
	if err := r1b.BigRCommitment.Validate(); err != nil {
		return errs.WrapValidation(err, "commitment validation failed")
	}
	return nil
}

func (r2b *Round2Broadcast) Validate(protocol types.ThresholdSignatureProtocol) error {
	if r2b.BigRProof == nil {
		return errs.NewIsNil("big r proof")
	}
	if r2b.BigR == nil {
		return errs.NewIsNil("big r")
	}
	if r2b.BigR.Curve() != protocol.Curve() {
		return errs.NewCurve("big r curve %s does not match protocol curve %s", r2b.BigR.Curve(), protocol.Curve())
	}
	if r2b.BigR.IsAdditiveIdentity() {
		return errs.NewIsIdentity("big r")
	}
	if err := r2b.BigROpening.Validate(); err != nil {
		return errs.WrapValidation(err, "could not validate opening")
	}
	return nil
}
