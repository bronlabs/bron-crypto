package znstar

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/crtp"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

type unitGroup[U any] interface {
	crtp.MultiplicativeGroup[U]
	crtp.MultiplicativeSemiModule[U, *num.Nat]
	crtp.Quotient[U, *num.NatPlus, *num.Uint]

	ModulusCT() *numct.Modulus
	Random(io.Reader) (U, error)
	AmbientGroup() *num.ZMod
	FromUint(*num.Uint) (U, error)
	FromNatCT(*numct.Nat) (U, error)
}
type UnitGroup[U unit[U]] unitGroup[U]

type KnowledgeOfOrder[A modular.Arithmetic, G UnitGroup[U], U Unit[U]] interface {
	Arithmetic() A
	ForgetOrder() G
}

type unit[U any] interface {
	crtp.MultiplicativeGroupElement[U]
	crtp.MultiplicativeSemiModuleElement[U, *num.Nat]
	crtp.Residue[U, *num.NatPlus]

	IsUnknownOrder() bool
	ModulusCT() *numct.Modulus
	algebra.ExponentiationBase[U, *num.Nat]
	algebra.IntegerExponentiationBase[U, *num.Int]
	base.Transparent[*num.Uint]
	base.Clonable[U]
}

type Unit[U unit[U]] unit[U]
