package dkls23

import (
	"github.com/bronlabs/krypton-primitives/pkg/base"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/network"
	"github.com/bronlabs/krypton-primitives/pkg/ot/extension/softspoken"
)

var _ network.Message[types.Protocol] = (*Round2Output)(nil)

type Round1Output = softspoken.Round1Output

type Round2Output struct {
	ATilde [Xi][LOTe]curves.Scalar
	Eta    [Rho]curves.Scalar
	Mu     []byte

	_ ds.Incomparable
}

func (r *Round2Output) Validate(protocol types.Protocol) error {
	for j := 0; j < Xi; j++ {
		for l := 0; l < LOTe; l++ {
			if r.ATilde[j][l] == nil {
				return errs.NewIsNil("a_tilde[%d][%d]", j, l)
			}
			if r.ATilde[j][l].IsZero() {
				return errs.NewIsZero("a_tilde[%d][%d]", j, l)
			}
		}
	}
	for i := 0; i < Rho; i++ {
		if r.Eta[i] == nil {
			return errs.NewIsNil("eta[%d]", i)
		}
		if r.Eta[i].IsZero() {
			return errs.NewIsZero("eta[%d]", i)
		}
	}
	if len(r.Mu) != base.CollisionResistanceBytes {
		return errs.NewLength("len(mu) != %d,  got %d", base.CollisionResistanceBytes, len(r.Mu))
	}
	return nil
}
