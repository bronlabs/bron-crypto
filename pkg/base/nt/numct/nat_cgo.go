//go:build !purego && !nobignum

package numct

import (
	"github.com/bronlabs/bron-crypto/pkg/base/cgo/boring"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

// GCD sets n = gcd(x, y) using boringssl based implementation.
// It leaks whether at least one of the elements are even or one is zero. For crypto applications,
// this should be fine given that that's almost never the case.
func (n *Nat) GCD(x, y *Nat) {
	if x.IsZero()&y.IsZero() == ct.True {
		n.SetZero() // gcd(0, 0) = 0 by convention
	} else if x.IsZero() == ct.True {
		n.Set(y)
	} else if y.IsZero() == ct.True {
		n.Set(x)
	} else if x.IsOdd()&y.IsOdd() == ct.True { // boringssl GCD constant time only if at least one element is odd.
		xBytes, yBytes := x.Bytes(), y.Bytes()
		xNum, err := boring.NewBigNum().SetBytes(xBytes)
		if err != nil {
			panic(err)
		}
		yNum, err := boring.NewBigNum().SetBytes(yBytes)
		if err != nil {
			panic(err)
		}
		bnCtx := boring.NewBigNumCtx()
		outNum, err := boring.NewBigNum().Gcd(xNum, yNum, bnCtx)
		if err != nil {
			panic(err)
		}
		outBytes, err := outNum.Bytes()
		if err != nil {
			panic(err)
		}
		n.SetBytes(outBytes)
	} else {
		var xy, lcm Nat
		xy.Mul(x, y)
		LCM(&lcm, x, y)
		denom, _ := NewModulus(&lcm)
		n.DivCap(&xy, denom, -1)
	}
}
