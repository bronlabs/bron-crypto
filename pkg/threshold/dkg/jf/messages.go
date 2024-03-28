package jf

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
)

var _ network.Message = (*Round1Broadcast)(nil)
var _ network.Message = (*Round1P2P)(nil)
var _ network.Message = (*Round2Broadcast)(nil)

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
	Commitments      []curves.Point
	CommitmentsProof compiler.NIZKPoKProof

	_ ds.Incomparable
}

func (r1b *Round1Broadcast) Validate(threshold ...int) error {
	t := threshold[0]
	if len(r1b.BlindedCommitments) == 0 {
		return errs.NewSize("blinded commitments is empty")
	}
	if len(r1b.BlindedCommitments) != t {
		return errs.NewLength("len(blindedCommitments) == %d != t == %d", len(r1b.BlindedCommitments), t)
	}
	return nil
}

func (r1p2p *Round1P2P) Validate(none ...int) error {
	if r1p2p.X_ij == nil {
		return errs.NewIsNil("x_ij")
	}
	if r1p2p.XPrime_ij == nil {
		return errs.NewIsNil("xPrime_ij")
	}
	return nil
}

func (r2b *Round2Broadcast) Validate(threshold ...int) error {
	t := threshold[0]
	if len(r2b.Commitments) == 0 {
		return errs.NewSize("commitments is empty")
	}

	if len(r2b.Commitments) != t {
		return errs.NewLength("len(senderCommitmentVector) == %d != t == %d", len(r2b.Commitments), t)
	}
	if r2b.CommitmentsProof == nil {
		return errs.NewIsNil("commitments proof")
	}
	return nil
}
