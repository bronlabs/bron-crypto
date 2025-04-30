package interactive_signing

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	hashcommitments "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/rprzs/setup"
)

var _ network.Message[types.ThresholdSignatureProtocol] = (*Round1Broadcast)(nil)
var _ network.Message[types.ThresholdSignatureProtocol] = (*Round2Broadcast)(nil)

type Round1Broadcast struct {
	BigRCommitment hashcommitments.Commitment

	_ ds.Incomparable
}

type Round1P2P = setup.Round1P2P

type Round2Broadcast struct {
	BigRProof   compiler.NIZKPoKProof
	BigR        curves.Point
	BigROpening hashcommitments.Witness

	_ ds.Incomparable
}

type Round2P2P = setup.Round2P2P

func (*Round1Broadcast) Validate(types.ThresholdSignatureProtocol) error {
	// if err := r1b.BigRCommitment.Validate(); err != nil {
	//	return errs.WrapValidation(err, "commitment validation failed")
	//}
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
	// if err := r2b.BigROpening.Validate(); err != nil {
	//	return errs.WrapValidation(err, "could not validate opening")
	//}
	return nil
}
