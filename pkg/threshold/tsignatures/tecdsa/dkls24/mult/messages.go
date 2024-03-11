package mult

import (
	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/ot/extension/softspoken"
)

var _ network.MessageLike = (*Round2Output)(nil)

type Round1Output = softspoken.Round1Output

type Round2Output struct {
	ATilde [Xi][LOTe]curves.Scalar
	Eta    [Rho]curves.Scalar
	Mu     []byte

	_ ds.Incomparable
}

func (r *Round2Output) Validate(none ...int) error {
	if len(r.Mu) != base.CollisionResistanceBytes {
		return errs.NewLength("len(mu) != %d,  got %d", base.CollisionResistanceBytes, len(r.Mu))
	}
	return nil
}
