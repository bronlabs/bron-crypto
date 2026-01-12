package mpc

var Ed25519Order = [4]*Value64{
	NewValue64Public(0x5812631a5cf5d3ed),
	NewValue64Public(0x14def9dea2f79cd6),
	NewValue64Public(0x0000000000000000),
	NewValue64Public(0x1000000000000000),
}

type Ed25519Scalar [4]*Value64

type Ed25519Arithmetic struct {
	arith *Arithmetic
}

func NewEd25519Arithmetic(arith *Arithmetic) *Ed25519Arithmetic {
	return &Ed25519Arithmetic{arith}
}

func (a *Ed25519Arithmetic) ScalarSelect(choice *Value64, c0, c1 Ed25519Scalar) Ed25519Scalar {
	mask := choice.BitMaskOf(0)
	maskNot := a.arith.Not(mask)

	andResult := a.arith.AndBatch(
		[]*Value64{c0[0], c0[1], c0[2], c0[3], c1[0], c1[1], c1[2], c1[3]},
		[]*Value64{maskNot, maskNot, maskNot, maskNot, mask, mask, mask, mask},
	)
	return [4]*Value64{
		a.arith.Xor(andResult[0], andResult[4]),
		a.arith.Xor(andResult[1], andResult[5]),
		a.arith.Xor(andResult[2], andResult[6]),
		a.arith.Xor(andResult[3], andResult[7]),
	}
}

// ScalarRandom returns a random scalar
// It is not perfectly uniform, but good enough
func (a *Ed25519Arithmetic) ScalarRandom() Ed25519Scalar {
	s := [4]*Value64{
		a.arith.RandomSecret(),
		a.arith.RandomSecret(),
		a.arith.RandomSecret(),
		a.arith.RandomSecret(),
	}

	return a.U256ReduceToScalar(s)
}

func (a *Ed25519Arithmetic) ScalarAdd(x, y Ed25519Scalar) Ed25519Scalar {
	var xy, t Ed25519Scalar
	var carryBorrow *Value64

	xy[0], carryBorrow = a.arith.AddCarry(x[0], y[0], NewValue64Public(0))
	xy[1], carryBorrow = a.arith.AddCarry(x[1], y[1], carryBorrow)
	xy[2], carryBorrow = a.arith.AddCarry(x[2], y[2], carryBorrow)
	xy[3], _ = a.arith.AddCarry(x[3], y[3], carryBorrow)

	t[0], carryBorrow = a.arith.SubBorrow(xy[0], Ed25519Order[0], NewValue64Public(0))
	t[1], carryBorrow = a.arith.SubBorrow(xy[1], Ed25519Order[1], carryBorrow)
	t[2], carryBorrow = a.arith.SubBorrow(xy[2], Ed25519Order[2], carryBorrow)
	t[3], carryBorrow = a.arith.SubBorrow(xy[3], Ed25519Order[3], carryBorrow)

	return a.ScalarSelect(carryBorrow, t, xy)
}

func (a *Ed25519Arithmetic) ScalarSub(x, y Ed25519Scalar) Ed25519Scalar {
	var xy, t Ed25519Scalar
	var carryBorrow *Value64

	xy[0], carryBorrow = a.arith.SubBorrow(x[0], y[0], NewValue64Public(0))
	xy[1], carryBorrow = a.arith.SubBorrow(x[1], y[1], carryBorrow)
	xy[2], carryBorrow = a.arith.SubBorrow(x[2], y[2], carryBorrow)
	xy[3], _ = a.arith.SubBorrow(x[3], y[3], carryBorrow)

	t[0], carryBorrow = a.arith.AddCarry(xy[0], Ed25519Order[0], NewValue64Public(0))
	t[1], carryBorrow = a.arith.AddCarry(xy[1], Ed25519Order[1], carryBorrow)
	t[2], carryBorrow = a.arith.AddCarry(xy[2], Ed25519Order[2], carryBorrow)
	t[3], carryBorrow = a.arith.AddCarry(xy[3], Ed25519Order[3], carryBorrow)

	return a.ScalarSelect(carryBorrow, xy, t)
}

func (a *Ed25519Arithmetic) U256ReduceToScalar(s [4]*Value64) Ed25519Scalar {
	// At most 15 actual subtractions are needed.
	// We run exactly 16 iterations to be safe.
	for range 16 {
		var t Ed25519Scalar
		var borrow *Value64
		t[0], borrow = a.arith.SubBorrow(s[0], Ed25519Order[0], NewValue64Public(0))
		t[1], borrow = a.arith.SubBorrow(s[1], Ed25519Order[1], borrow)
		t[2], borrow = a.arith.SubBorrow(s[2], Ed25519Order[2], borrow)
		t[3], borrow = a.arith.SubBorrow(s[3], Ed25519Order[3], borrow)

		s = a.ScalarSelect(borrow, t, s)
	}

	return s
}
