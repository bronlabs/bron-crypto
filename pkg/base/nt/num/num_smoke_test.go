package num_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
)

var (
	_ algebra.NPlusLike[*num.NatPlus]   = (*num.PositiveNaturalNumbers)(nil)
	_ algebra.NatPlusLike[*num.NatPlus] = (*num.NatPlus)(nil)

	_ algebra.NLike[*num.Nat]                       = (*num.NaturalNumbers)(nil)
	_ algebra.NatLike[*num.Nat]                     = (*num.Nat)(nil)
	_ algebra.SemiModule[*num.Nat, *num.Nat]        = (*num.NaturalNumbers)(nil)
	_ algebra.SemiModuleElement[*num.Nat, *num.Nat] = (*num.Nat)(nil)

	_ algebra.ZLike[*num.Int]                   = (*num.Integers)(nil)
	_ algebra.IntLike[*num.Int]                 = (*num.Int)(nil)
	_ algebra.Module[*num.Int, *num.Int]        = (*num.Integers)(nil)
	_ algebra.ModuleElement[*num.Int, *num.Int] = (*num.Int)(nil)

	_ algebra.ZModLike[*num.Uint]                    = (*num.ZMod)(nil)
	_ algebra.UintLike[*num.Uint]                    = (*num.Uint)(nil)
	_ algebra.SemiModule[*num.Uint, *num.Nat]        = (*num.ZMod)(nil)
	_ algebra.SemiModuleElement[*num.Uint, *num.Nat] = (*num.Uint)(nil)

	_ algebra.Field[*num.Rat]        = (*num.Rationals)(nil)
	_ algebra.FieldElement[*num.Rat] = (*num.Rat)(nil)
)
