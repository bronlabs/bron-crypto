package znstar

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

type UnitGroup interface {
	algebra.MultiplicativeGroup[Unit]
	algebra.MultiplicativeSemiModule[Unit, *num.Nat]
	algebra.Quotient[Unit, *num.NatPlus, *num.Uint]

	ModulusCT() numct.Modulus
	Random(io.Reader) (Unit, error)
	AmbientGroup() *num.ZMod
	FromUint(*num.Uint) (Unit, error)
	FromNatCT(*numct.Nat) (Unit, error)
}

type KnowledgeOfOrder[A modular.Arithmetic, G UnitGroup] interface {
	Arithmetic() A
	ForgetOrder() G
}

type Unit interface {
	algebra.MultiplicativeGroupElement[Unit]
	algebra.MultiplicativeSemiModuleElement[Unit, *num.Nat]
	algebra.Residue[Unit, *num.NatPlus]

	IsUnknownOrder() bool
	Group() UnitGroup
	ModulusCT() numct.Modulus
	ForgetOrder() Unit
	LearnOrder(UnitGroup) Unit
	algebra.ExponentiationBase[Unit, *num.Nat]
	algebra.IntegerExponentiationBase[Unit, *num.Int]
	base.Transparent[*num.Uint]
	base.Clonable[Unit]
}
