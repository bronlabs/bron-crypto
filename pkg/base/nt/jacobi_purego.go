//go:build purego || nobignum

package nt

import "github.com/bronlabs/errs-go/errs"

// Jacobi returns the Jacobi symbol (x/y) for a positive odd y. It is a pure-Go
// port of BoringSSL's BN_jacobi (itself an adaptation of Cohen's algorithm
// 1.4.10 for the Kronecker symbol); see
// https://github.com/google/boringssl/blob/67a6614cf3be3b2d63262be94a1fba86a4e4e92d/crypto/fipsmodule/bn/jacobi.cc.inc#L27
// Negative x is first reduced mod y, which does not change the result.
//
// NOT constant time: the iteration count depends on the quotient sequence of
// (x, y), the inner loop strips trailing zero bits one at a time, and the
// modular reduction routes through variable-time math/big arithmetic. Do not
// use on secret inputs.
func Jacobi(x *num.Int, y *num.NatPlus) (int, error) {
	// In 'tab', only odd-indexed entries are relevant:
	// For any odd Nat n tab[n.Byte(0) & 0b111] is $(-1)^{(n^2-1)/8}$ (using TeX notation).
	// Note that the sign of n does not matter.
	jacobiTab := [8]int{0, 1, 0, -1, 0, -1, 0, 1}
	b := y.Clone()
	if b.IsEven() {
		return -2, ErrInvalidArgument.WithMessage("Jacobi symbol is only defined for odd positive y")
	}
	a := x.Abs()
	if x.IsNegative() {
		a = a.Mod(b).Nat() // BoringSSL does not support negative inputs for Jacobi, so we take the absolute value and adjust the result accordingly
	}

	// Adapted from logic to compute the Kronecker symbol, originally implemented according to Henri Cohen,
	// "A Course in Computational Algebraic Number Theory" (algorithm 1.4.10).
	ret := 1
	for {
		// Cohen's step 3:

		if a.IsZero() {
			if !b.IsOne() {
				ret = 0
			}
			break
		}

		// now A is non-zero
		i := 0
		for a.Value().Big().Bit(i) == 0 {
			i++
		}
		a = a.Rsh(uint(i))
		if (i & 1) != 0 {
			// i is odd
			// multiply 'ret' by  $(-1)^{(B^2-1)/8}$
			ret *= jacobiTab[b.Byte(0)&0b111]
		}

		// Cohen's step 4:
		// multiply 'ret' by  $(-1)^{(A-1)(B-1)/4}$
		if (a.Byte(0) & b.Byte(0) & 0b10) != 0 {
			ret = -ret
		}

		// (a, b) := (b mod a, a)
		aAsNatPlus, err := num.NPlus().FromNat(a)
		if err != nil {
			return -2, errs.Wrap(err).WithMessage("failed to convert a to NatPlus")
		}
		bModA := b.Mod(aAsNatPlus)
		a, b = bModA.Nat(), aAsNatPlus
	}
	return ret, nil
}
