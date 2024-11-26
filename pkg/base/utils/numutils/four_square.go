package numutils

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils/safecast"
	saferith_utils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
)

var (
	zero = new(saferith.Nat).SetUint64(0)
	one  = new(saferith.Nat).SetUint64(1)
)

func pairByModTwo(w1, w2, w3, w4 *saferith.Nat) (w1Out, w2Out, w3Out, w4Out *saferith.Nat) {
	if saferith_utils.NatIsOdd(w1) == saferith_utils.NatIsOdd(w2) {
		return w1, w2, w3, w4
	}

	if saferith_utils.NatIsOdd(w2) == saferith_utils.NatIsOdd(w3) {
		return w1, w4, w3, w2
	}

	return w1, w3, w2, w4
}

func decompose(mu *saferith.Nat) (uint, *saferith.Nat) {
	t := uint(0)
	k := mu.Clone()
	for !saferith_utils.NatIsOdd(k) {
		k.Rsh(k, 1, -1)
		t++
	}

	return t, k
}

func euclidianAdhoc(u, p *saferith.Nat) (r, uOut *saferith.Nat) {
	r = new(saferith.Nat).Mod(p, saferith.ModulusFromNat(u))
	for saferith_utils.NatIsLess(p, new(saferith.Nat).Mul(u, u, -1)) {
		a := u
		u = r
		if u.EqZero() != 1 {
			r = new(saferith.Nat).Mod(a, saferith.ModulusFromNat(u))
		}
	}

	return r, u
}

func sampleW1W2(prng io.Reader, mu *saferith.Nat) (w1, w2 *saferith.Nat, err error) {
	for {
		w1, err := saferith_utils.NatRandomBits(prng, safecast.MustToUint(mu.TrueLen()/2+1))
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not produce a nat from random bits")
		}

		w2, err := saferith_utils.NatRandomBits(prng, safecast.MustToUint(mu.TrueLen()/2+1))
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not produce a nat from random bits")
		}

		w1Square := new(saferith.Nat).Mul(w1, w1, -1)
		w2Square := new(saferith.Nat).Mul(w2, w2, -1)
		squareSum := new(saferith.Nat).Add(w1Square, w2Square, -1)
		if (saferith_utils.NatIsOdd(w1) != saferith_utils.NatIsOdd(w2)) &&
			saferith_utils.NatIsLess(squareSum, mu) {

			return w1, w2, nil
		}
	}
}

func sqrtMinusOne(prng io.Reader, p *saferith.Nat) (bool, *saferith.Nat, error) {
	pMinusOne := saferith_utils.NatDec(p)
	pModulus := saferith.ModulusFromNat(p)
	rand, err := saferith_utils.NatRandomRangeH(prng, p)
	if err != nil {
		return false, nil, errs.WrapFailed(err, "could not produce a random nat from range")
	}

	if new(saferith.Nat).Exp(rand, pMinusOne, pModulus).Eq(one) != 1 {
		return false, nil, nil
	}

	pQuarter := new(saferith.Nat).Rsh(pMinusOne, uint(2), -1)
	for i := 0; i < 4; i++ {
		uSqrt := new(saferith.Nat).Exp(rand, pQuarter, pModulus)
		u := new(saferith.Nat).ModMul(uSqrt, uSqrt, pModulus)
		if u.Eq(pMinusOne) == 1 {
			return true, uSqrt, nil
		}

		rand, err = saferith_utils.NatRandomRangeH(prng, p)
		if err != nil {
			return false, nil, errs.WrapFailed(err, "could not produce a random nat from range")
		}
	}

	return false, nil, nil
}

func sampleW3W4(prng io.Reader, p *saferith.Nat) (exists bool, w3, w4 *saferith.Nat, err error) {
	if p.EqZero() == 1 {
		return true, zero, zero, nil
	}

	if p.Eq(one) == 1 {
		return true, one, zero, nil
	}

	exists, sqrt, err := sqrtMinusOne(prng, p)
	if exists {
		w3, w4 := euclidianAdhoc(sqrt, p)
		if p.Eq(new(saferith.Nat).Add(new(saferith.Nat).Mul(w3, w3, -1), new(saferith.Nat).Mul(w4, w4, -1), -1)) == 1 {
			return true, w3, w4, err
		}
	}

	return false, nil, nil, nil
}

func getFourSquaresOne(prng io.Reader, mu *saferith.Nat) (w1, w2, w3, w4 *saferith.Nat, err error) {
	for {
		w1, w2, err := sampleW1W2(prng, mu)
		if err != nil {
			return nil, nil, nil, nil, errs.WrapFailed(err, "error sampleW1W2")
		}

		w1Square := new(saferith.Nat).Mul(w1, w1, -1)
		w2Square := new(saferith.Nat).Mul(w2, w2, -1)
		sumOfSquares := new(saferith.Nat).Add(w1Square, w2Square, -1)
		p := new(saferith.Nat).Sub(mu, sumOfSquares, -1)
		exists, w3, w4, err := sampleW3W4(prng, p)
		if err != nil {
			return nil, nil, nil, nil, errs.WrapFailed(err, "error sampleW3W4")
		}

		if exists {
			return w1, w2, w3, w4, nil
		}
	}
}

func getFourSquaresOdd(prng io.Reader, mu *saferith.Nat, t uint) (w1, w2, w3, w4 *saferith.Nat, err error) {
	s := new(saferith.Nat).Lsh(one, (t-1)/2, -1)
	w1, w2, w3, w4, err = getFourSquaresOne(prng, new(saferith.Nat).Rsh(mu, t-1, -1))
	if err != nil {
		return nil, nil, nil, nil, errs.WrapFailed(err, "error GetFourSquare")
	}

	w1 = new(saferith.Nat).Mul(s, w1, -1)
	w2 = new(saferith.Nat).Mul(s, w2, -1)
	w3 = new(saferith.Nat).Mul(s, w3, -1)
	w4 = new(saferith.Nat).Mul(s, w4, -1)
	return w1, w2, w3, w4, nil
}

func finalComputationZero(w1, w2, w3, w4 *saferith.Nat) (w1Out, w2Out, w3Out, w4Out *saferith.Nat, err error) {
	w1tmp := new(saferith.Nat).Rsh(new(saferith.Nat).Add(w1, w2, -1), 1, -1)
	if saferith_utils.NatIsLess(w2, w1) {
		w2 = new(saferith.Nat).Rsh(new(saferith.Nat).Sub(w1, w2, -1), 1, -1)
	} else {
		w2 = new(saferith.Nat).Rsh(new(saferith.Nat).Sub(w2, w1, -1), 1, -1)
	}

	w3tmp := new(saferith.Nat).Rsh(new(saferith.Nat).Add(w3, w4, -1), 1, -1)
	if saferith_utils.NatIsLess(w4, w3) {
		w4 = new(saferith.Nat).Rsh(new(saferith.Nat).Sub(w3, w4, -1), 1, -1)
	} else {
		w4 = new(saferith.Nat).Rsh(new(saferith.Nat).Sub(w4, w3, -1), 1, -1)
	}

	return w1tmp, w2, w3tmp, w4, nil
}

func finalComputationNonZero(t uint, w1, w2, w3, w4 *saferith.Nat) (w1Out, w2Out, w3Out, w4Out *saferith.Nat, err error) {
	s := new(saferith.Nat).Lsh(one, t/2-1, -1)
	w1Temp := new(saferith.Nat).Mul(new(saferith.Nat).Add(w1, w2, -1), s, -1)
	if saferith_utils.NatIsLess(w2, w1) {
		w2 = new(saferith.Nat).Mul(new(saferith.Nat).Sub(w1, w2, -1), s, -1)
	} else {
		w2 = new(saferith.Nat).Mul(new(saferith.Nat).Sub(w2, w1, -1), s, -1)
	}

	w3Temp := new(saferith.Nat).Mul(new(saferith.Nat).Add(w3, w4, -1), s, -1)
	if saferith_utils.NatIsLess(w4, w3) {
		w4 = new(saferith.Nat).Mul(new(saferith.Nat).Sub(w3, w4, -1), s, -1)
	} else {
		w4 = new(saferith.Nat).Mul(new(saferith.Nat).Sub(w4, w3, -1), s, -1)
	}

	return w1Temp, w2, w3Temp, w4, nil
}

func getFourSquaresEven(prng io.Reader, t uint, k *saferith.Nat) (w1, w2, w3, w4 *saferith.Nat, err error) {
	w1, w2, w3, w4, err = getFourSquaresOne(prng, new(saferith.Nat).Lsh(k, 1, -1))
	if err != nil {
		return nil, nil, nil, nil, errs.WrapFailed(err, "error GetFourSquare")
	}

	w1, w2, w3, w4 = pairByModTwo(w1, w2, w3, w4)
	if t == 0 {
		return finalComputationZero(w1, w2, w3, w4)
	}

	return finalComputationNonZero(t, w1, w2, w3, w4)
}

func GetFourSquares(prng io.Reader, mu *saferith.Nat) (w1, w2, w3, w4 *saferith.Nat, err error) {
	if mu.EqZero() == 1 {
		return zero, zero, zero, zero, nil
	}

	t, k := decompose(mu)
	if t == 1 {
		return getFourSquaresOne(prng, mu)
	}

	if t%2 == 1 {
		return getFourSquaresOdd(prng, mu, t)
	}

	return getFourSquaresEven(prng, t, k)
}
