//go:build purego || nobignum

package numct

import "github.com/bronlabs/bron-crypto/pkg/base/ct"

// GCD sets n = gcd(x, y) using a constant-time (w.r.t. announced capacity)
// binary GCD (Stein) algorithm. The result is always non-negative and
// gcd(0, 0) = 0.
func (n *Nat) GCD(x, y *Nat) {
	if x == nil || y == nil {
		panic("numct.Nat.GCD: nil input")
	}

	var u, v Nat
	u.Set(x)
	v.Set(y)

	// Capacity in bits: public / announced length.
	capBits := max(u.AnnouncedLen(), v.AnnouncedLen())
	if capBits <= 0 {
		capBits = 1
	}

	u.Resize(capBits)
	v.Resize(capBits)

	var tmpUShift, tmpVShift Nat
	var tmpDiff1, tmpDiff2 Nat
	tmpUShift.Resize(capBits)
	tmpVShift.Resize(capBits)
	tmpDiff1.Resize(capBits)
	tmpDiff2.Resize(capBits)

	one := ct.Choice(1)
	active := one

	// shift holds the common factor 2^shift such that gcd(x, y) = oddGcd * 2^shift.
	shift := 0

	// Upper bound on the number of Stein steps: <= log2(u) + log2(v) <= 2 * capBits.
	maxIters := 2 * capBits

	for range maxIters {
		uZero := u.IsZero()
		vZero := v.IsZero()
		terminate := uZero | vZero

		stepActive := active & ct.Choice(terminate.Not())

		// Parities from low byte.
		lsbU := u.Byte(0) & 1
		lsbV := v.Byte(0) & 1

		uOdd := ct.Choice(lsbU)
		vOdd := ct.Choice(lsbV)
		uEven := one ^ uOdd
		vEven := one ^ vOdd

		// Mutually exclusive parity cases.
		evenEven := uEven & vEven
		evenOdd := uEven & vOdd
		oddEven := uOdd & vEven
		oddOdd := uOdd & vOdd

		doEvenEven := stepActive & evenEven
		doEvenOdd := stepActive & evenOdd
		doOddEven := stepActive & oddEven
		doOddOdd := stepActive & oddOdd

		// ----- Even cases (Stein identities on factors of 2) -----

		// Precompute single-bit right shifts.
		tmpUShift.RshCap(&u, 1, capBits)
		tmpVShift.RshCap(&v, 1, capBits)

		// If both even: u >>= 1, v >>= 1, shift++
		// If only u even: u >>= 1
		// If only v even: v >>= 1
		u.CondAssign(doEvenEven|doEvenOdd, &tmpUShift)
		v.CondAssign(doEvenEven|doOddEven, &tmpVShift)

		// Update the 2-adic gcd factor; doEvenEven is 1 exactly when we halved both.
		if doEvenEven != 0 {
			shift++
		}

		// ----- Odd / odd case -----
		// When u and v are odd, Stein uses:
		//   if u >= v: u = (u - v)/2
		//   else:      v = (v - u)/2

		// Compute (u - v)/2 and (v - u)/2 (both mod 2^capBits, but only one is used).
		tmpDiff1.SubCap(&u, &v, capBits)       // u - v (mod 2^capBits)
		tmpDiff1.RshCap(&tmpDiff1, 1, capBits) // (u - v)/2

		tmpDiff2.SubCap(&v, &u, capBits)       // v - u (mod 2^capBits)
		tmpDiff2.RshCap(&tmpDiff2, 1, capBits) // (v - u)/2

		_, eq, gt := u.Compare(&v)
		uGeV := gt | eq // 1 if u >= v, 0 otherwise

		updateU := doOddOdd & ct.Choice(uGeV)         // odd/odd and u >= v  -> update u
		updateV := doOddOdd & (one ^ ct.Choice(uGeV)) // odd/odd and u <  v -> update v

		u.CondAssign(updateU, &tmpDiff1)
		v.CondAssign(updateV, &tmpDiff2)

		// Once either argument hits zero, freeze the state.
		active = active & ct.Choice(terminate.Not())
	}

	// At this point, one of u, v is zero; the other is gcd(x, y) / 2^shift.
	var gOdd Nat
	gOdd.Resize(capBits)
	gOdd.AddCap(&u, &v, capBits) // u + v = non-zero argument (since the other is 0)

	// Re-introduce the factor 2^shift without using a secret shift count for Lsh.
	// We run capBits iterations, each time doubling and conditionally accepting it
	// if i < shift, so we effectively perform exactly 'shift' doublings.
	var res Nat
	res.Resize(capBits)
	res.Set(&gOdd)

	var dbl Nat
	dbl.Resize(capBits)

	maxShift := capBits
	for i := range maxShift {
		// tmp = res << 1 (constant shift, safe w.r.t. timing model).
		dbl.LshCap(&res, 1, capBits)

		// cond = 1 if i < shift, 0 otherwise, computed without branches.
		d64 := int64(shift - 1 - i)
		// sign = 0 if d64 >= 0, -1 if d64 < 0.
		var sign int64 = d64 >> 63
		condVal := uint8(^sign & 1)
		cond := ct.Choice(condVal)

		res.CondAssign(cond, &dbl)
	}

	n.Set(&res)
}
