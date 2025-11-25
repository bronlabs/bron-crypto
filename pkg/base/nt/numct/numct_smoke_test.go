package numct_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/nt/internal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

var (
	_ (internal.NatMutable[*numct.Nat, *numct.Modulus])                 = (*numct.Nat)(nil)
	_ (internal.IntMutable[*numct.Int, *numct.Modulus])                 = (*numct.Int)(nil)
	_ (internal.ModulusMutable[*numct.Int, *numct.Nat, *numct.Modulus]) = (*numct.Modulus)(nil)
)
