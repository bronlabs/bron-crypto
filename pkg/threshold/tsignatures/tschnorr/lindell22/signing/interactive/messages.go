package interactive_signing

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/setup"
)

var _ network.MessageLike = (*Round1Broadcast)(nil)
var _ network.MessageLike = (*Round1P2P)(nil)
var _ network.MessageLike = (*Round2Broadcast)(nil)
var _ network.MessageLike = (*Round2P2P)(nil)

type Round1Broadcast struct {
	BigRCommitment commitments.Commitment

	_ ds.Incomparable
}

type Round1P2P = setup.Round1P2P

type Round2Broadcast struct {
	BigRProof   compiler.NIZKPoKProof
	BigR        curves.Point
	BigRWitness commitments.Witness

	_ ds.Incomparable
}

type Round2P2P = setup.Round2P2P

func (r1b *Round1Broadcast) Validate(none ...int) error {
	if r1b.BigRCommitment == nil {
		return errs.NewIsNil("big r commitment")
	}
	return nil
}

func (r2b *Round2Broadcast) Validate(none ...int) error {
	if r2b.BigRProof == nil {
		return errs.NewIsNil("big r proof")
	}
	if r2b.BigR == nil {
		return errs.NewIsNil("big r")
	}
	if r2b.BigRWitness == nil {
		return errs.NewIsNil("big r witness")
	}
	return nil
}
