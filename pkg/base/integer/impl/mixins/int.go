package mixins

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/domain"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
)

type Z[S integer.Z[S, E], E integer.Int[S, E]] struct {
	NaturalRig[S, E]
	domain.EuclideanDomain[S, E]
}

type Int[S integer.Z[S, E], E integer.Int[S, E]] struct {
	NaturalRigElement[S, E]
	domain.EuclideanDomainElement[S, E]

	H HolesInt[S, E]
}

func (n *Int[S, E]) Abs() E {
	return n.H.Arithmetic().Abs(n.H.Unwrap())
}

func (n *Int[S, E]) Neg() E {
	out, err := n.H.Arithmetic().Neg(n.H.Unwrap())
	if err != nil {
		panic(errs.WrapFailed(err, "couldn't negate int"))
	}
	return out
}
