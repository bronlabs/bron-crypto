//go:build !purego && !nobignum

package numct

import (
	"github.com/bronlabs/bron-crypto/pkg/base/cgo/boring"
	"github.com/cronokirby/saferith"
)

// GCD sets n = gcd(x, y) using boringssl based implementation.
func (n *Nat) GCD(x, y *Nat) {
	c := min(((*saferith.Nat)(x)).AnnouncedLen(), ((*saferith.Nat)(y)).AnnouncedLen())

	var u, v, tu, tv, t, shift saferith.Nat
	shift.SetUint64(1).Resize(c)
	u.SetNat((*saferith.Nat)(x))
	v.SetNat((*saferith.Nat)(y))
	for range c {
		uEven := saferith.Choice(u.Byte(0)&0b1) ^ 0b1
		vEven := saferith.Choice(v.Byte(0)&0b1) ^ 0b1

		t.Lsh(&shift, 1, c)
		shift.CondAssign(uEven&vEven, &t)

		tu.Rsh(&u, 1, u.AnnouncedLen())
		tv.Rsh(&v, 1, v.AnnouncedLen())
		u.CondAssign(uEven&vEven, &tu)
		v.CondAssign(uEven&vEven, &tv)
	}

	uBytes, vBytes := u.Bytes(), v.Bytes()
	xNum, err := boring.NewBigNum().SetBytes(uBytes)
	if err != nil {
		panic(err)
	}
	yNum, err := boring.NewBigNum().SetBytes(vBytes)
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

	((*saferith.Nat)(n)).SetBytes(outBytes)
	((*saferith.Nat)(n)).Mul((*saferith.Nat)(n), &shift, max(x.AnnouncedLen(), y.AnnouncedLen()))
}
