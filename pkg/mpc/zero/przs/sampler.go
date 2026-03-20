package przs

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
)

// SampleZeroShare derives an additive share that sums to the group identity across the quorum.
func SampleZeroShare[GE algebra.GroupElement[GE]](ctx *session.Context, g algebra.FiniteGroup[GE]) (*additive.Share[GE], error) {
	if ctx == nil || g == nil {
		return nil, ErrInvalidArgument.WithMessage("input is nil")
	}
	value := g.OpIdentity()
	for id := range ctx.OtherPartiesOrdered() {
		v, err := g.Random(ctx.Seeds()[id])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not sample group element")
		}
		if id < ctx.HolderID() {
			v = v.OpInv()
		}
		value = value.Op(v)
	}

	as, err := unanimity.NewUnanimityAccessStructure(ctx.Quorum())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create access structure")
	}
	share, err := additive.NewShare(ctx.HolderID(), value, as)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create additive share")
	}
	return share, nil
}
