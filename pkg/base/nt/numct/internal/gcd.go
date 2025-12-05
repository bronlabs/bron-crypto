package internal

import "github.com/cronokirby/saferith"

// GCD sets n = gcd(x, y) using a constant-time (w.r.t. announced capacity) binary GCD (Stein) algorithm.
// The result is always non-negative and gcd(0, 0) = 0.
func GCD(x, y *saferith.Nat) *saferith.Nat {
	capacity := max(x.AnnouncedLen(), y.AnnouncedLen())

	var u, v, shift saferith.Nat
	u.SetNat(x).Resize(capacity)
	v.SetNat(y).Resize(capacity)
	shift.SetUint64(1).Resize(capacity)

	var t, tu, tv saferith.Nat
	for range 2 * capacity {
		uEven := saferith.Choice(u.Byte(0)&0b1) ^ 0b1
		vEven := saferith.Choice(v.Byte(0)&0b1) ^ 0b1
		tu.SetNat(&u)
		tu.Rsh(&tu, 1, capacity)
		u.CondAssign(uEven, &tu)
		tv.SetNat(&v)
		tv.Rsh(&tv, 1, capacity)
		v.CondAssign(vEven, &tv)
		t.SetNat(&shift)
		t.Lsh(&t, 1, capacity)
		shift.CondAssign(uEven&vEven, &t)

		// make v >= u
		t.SetNat(&u)
		uGreaterThanV, _, _ := u.Cmp(&v)
		u.CondAssign(uGreaterThanV, &v)
		v.CondAssign(uGreaterThanV, &t)

		uOdd := saferith.Choice(u.Byte(0) & 0b1)
		vOdd := saferith.Choice(v.Byte(0) & 0b1)
		t.Sub(&v, &u, capacity)
		v.CondAssign(uOdd&vOdd, &t)
	}

	return new(saferith.Nat).Mul(&v, &shift, capacity)
}
