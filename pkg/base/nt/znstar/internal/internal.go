package internal

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

type UnitGroup[U UnitCrtp[U]] interface {
	algebra.MultiplicativeGroup[U]
	algebra.MultiplicativeSemiModule[U, *num.Nat]
	algebra.Quotient[U, *num.NatPlus, *num.Uint]

	ModulusCT() numct.Modulus
	Random(io.Reader) (U, error)
	AmbientGroup() *num.ZMod
	FromUint(*num.Uint) (U, error)
	FromNatCT(*numct.Nat) (U, error)
}

type KnowledgeOfOrderCrtp[A, GF any] interface {
	Arithmetic() A
	ForgetOrder() GF
}

type KnowledgeOfOrder[A modular.Arithmetic, GF UnitGroup[UF], UF Unit[UF]] interface {
	Arithmetic() A
	ForgetOrder() GF
}

type UnitCrtp[U interface {
	algebra.MultiplicativeGroupElement[U]
	algebra.MultiplicativeSemiModuleElement[U, *num.Nat]
}] interface {
	algebra.MultiplicativeGroupElement[U]
	algebra.MultiplicativeSemiModuleElement[U, *num.Nat]
	algebra.Residue[U, *num.NatPlus]

	IsUnknownOrder() bool
	ModulusCT() numct.Modulus
	Cardinal() cardinal.Cardinal
	algebra.ExponentiationBase[U, *num.Nat]
	algebra.IntegerExponentiationBase[U, *num.Int]
	base.Transparent[*numct.Nat]
	base.Clonable[U]
}

type Unit[U UnitCrtp[U]] UnitCrtp[U]

// =================== Traits ===================

type UnitWrapper[G any, U Unit[U]] interface {
	Modulus() *num.NatPlus
	IsUnknownOrder() bool
	base.Transparent[*numct.Nat]
	setGroup(G)
	setValue(*numct.Nat)
	setModulus(numct.Modulus)
}

type UnitPtrConstraint[G any, U Unit[U], UT any] interface {
	*UT
	UnitWrapper[G, U]
}

func OperandsAreValid(x, y interface {
	Modulus() *num.NatPlus
	IsUnknownOrder() bool
}) error {
	if x == nil {
		return errs.NewIsNil("x")
	}
	if y == nil {
		return errs.NewIsNil("y")
	}
	if !x.Modulus().Equal(y.Modulus()) {
		return errs.NewValue("x and y must have the same modulus")
	}
	if x.IsUnknownOrder() != y.IsUnknownOrder() {
		return errs.NewValue("x and y must both be in known or unknown order groups")
	}
	return nil
}
