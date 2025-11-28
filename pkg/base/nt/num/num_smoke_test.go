package num

import "github.com/bronlabs/bron-crypto/pkg/base/algebra"

var (
	_ algebra.NPlusLike[*NatPlus]   = (*PositiveNaturalNumbers)(nil)
	_ algebra.NatPlusLike[*NatPlus] = (*NatPlus)(nil)

	_ algebra.NLike[*Nat]                   = (*NaturalNumbers)(nil)
	_ algebra.NatLike[*Nat]                 = (*Nat)(nil)
	_ algebra.SemiModule[*Nat, *Nat]        = (*NaturalNumbers)(nil)
	_ algebra.SemiModuleElement[*Nat, *Nat] = (*Nat)(nil)
)
