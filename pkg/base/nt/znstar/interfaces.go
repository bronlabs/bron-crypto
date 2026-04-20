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
	algebra.FiniteStructure[U]
	crtp.MultiplicativeGroup[U]
	crtp.MultiplicativeModule[U, *num.Int]
	crtp.Quotient[U, *num.NatPlus, *num.Uint]

	ModulusCT() *numct.Modulus
	Random(io.Reader) (U, error)
	AmbientGroup() *num.ZMod
	FromUint(*num.Uint) (U, error)
	FromNatCT(*numct.Nat) (U, error)
}

// UnitGroup is the abstract interface satisfied by every unit group
// (Z/NZ)* exposed by this package — RSA-modulus groups, Paillier n²-groups,
// and their unknown-order quotients. It bundles the algebraic structure
// (finite, multiplicative, acted on by Z as a Z-module), the quotient view
// onto the ambient ring Z/NZ, and the constructors needed to lift raw
// integers into the group after checking the unit (i.e. coprime-with-N)
// condition. Hiding the concrete group behind this interface lets the
// ZK-proof layer be written once against "any ring-Pedersen-style modulus".
type UnitGroup[U unit[U]] unitGroup[U]

// KnowledgeOfOrder marks a group whose trapdoor — the factorisation of N —
// is available internally (the concrete Arithmetic A carries p and q and
// enables CRT-accelerated ModExp). ForgetOrder projects the same group to
// its unknown-order view, which is what a verifier or a party without the
// factorisation holds. This pair captures the prover/verifier asymmetry at
// the type level so that, for instance, a ZK prover can sample in the
// known-order group and transport the group element to the verifier as a
// value in the unknown-order group by construction.
type KnowledgeOfOrder[A modular.Arithmetic, G UnitGroup[U], U Unit[U]] interface {
	Arithmetic() A
	ForgetOrder() G
}

type unit[U any] interface {
	crtp.MultiplicativeGroupElement[U]
	crtp.MultiplicativeModuleElement[U, *num.Int]
	crtp.Residue[U, *num.NatPlus]

	IsUnknownOrder() bool
	ModulusCT() *numct.Modulus
	algebra.ExponentiationBase[U, *num.Nat]
	algebra.IntegerExponentiationBase[U, *num.Int]
	base.Transparent[*num.Uint]
	base.Clonable[U]
}

// Unit is the abstract interface for an element of a unit group. It exposes
// multiplicative group operations, Z-module scalar actions (integer
// exponentiation with both *num.Nat and *num.Int exponents, mapped modulo
// the ambient order when that is known), the residue view (the underlying
// integer in the ambient ring), and IsUnknownOrder to query the trapdoor
// view that the concrete unit was constructed under.
type Unit[U unit[U]] unit[U]
