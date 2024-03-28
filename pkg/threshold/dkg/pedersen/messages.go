package pedersen

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
)

var _ network.Message = (*Round1Broadcast)(nil)
var _ network.Message = (*Round1P2P)(nil)

type Round1Broadcast struct {
	Ci        []curves.Point
	DlogProof compiler.NIZKPoKProof

	_ ds.Incomparable
}

type Round1P2P struct {
	Xij curves.Scalar

	_ ds.Incomparable
}

func (r1b *Round1Broadcast) Validate(threshold ...int) error {
	t := threshold[0]
	if len(r1b.Ci) == 0 {
		return errs.NewSize("ci is empty")
	}
	if len(r1b.Ci) != t {
		return errs.NewLength("len(ci) == %d != t == %d", len(r1b.Ci), t)
	}
	if r1b.DlogProof == nil {
		return errs.NewIsNil("dlog proof")
	}
	return nil
}

func (r1p2p *Round1P2P) Validate(none ...int) error {
	if r1p2p.Xij == nil {
		return errs.NewIsNil("x_ij")
	}
	return nil
}
