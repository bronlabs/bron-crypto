package saferith_utils

import (
	crand "crypto/rand"
	"io"
	"math/big"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type BigIntAdapter interface {
	Big() *big.Int
}

var (
	NatOne  = new(saferith.Nat).SetUint64(1).Resize(1)
	NatZero = new(saferith.Nat).SetUint64(0).Resize(1)

	// In 'tab', only odd-indexed entries are relevant:
	// For any odd Nat n tab[n.Byte(0) & 0b111] is $(-1)^{(n^2-1)/8}$ (using TeX notation).
	// Note that the sign of n does not matter.
	jacobiTab = [8]int{0, 1, 0, -1, 0, -1, 0, 1}
)

func NatJacobi(a, b *saferith.Nat) (int, error) {
	if !NatIsOdd(b) {
		return 0, errs.NewValue("called with even modulus")
	}

	// 2 * Bitlen - 1

	// Adapted from logic to compute the Kronecker symbol, originally implemented according to Henri Cohen,
	// "A Course in Computational Algebraic Number Theory" (algorithm 1.4.10).
	ret := 1
	for {
		// Cohen's step 3:

		// B is positive and odd
		if a.EqZero() != 0 {
			if b.Eq(NatOne) == 0 {
				ret = 0
			}
			break
		}

		// now A is non-zero
		i := uint(0)
		for NatGetBit(a, i) == 0 {
			i++
		}
		a = new(saferith.Nat).Rsh(a, i, -1)
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
		b = new(saferith.Nat).Mod(b, saferith.ModulusFromNat(a))
		a, b = b, a
	}

	return ret, nil
}

func NatInc(n *saferith.Nat) *saferith.Nat {
	return new(saferith.Nat).Add(n, NatOne, n.AnnouncedLen()+1)
}

func NatDec(n *saferith.Nat) *saferith.Nat {
	return new(saferith.Nat).Sub(n, NatOne, n.AnnouncedLen())
}

func NatFromBigMod(x *big.Int, m *saferith.Modulus) *saferith.Nat {
	xx := new(saferith.Nat).SetBig(x, x.BitLen())
	return new(saferith.Nat).Mod(xx, m)
}

func NatFromBytesMod(x []byte, m *saferith.Modulus) *saferith.Nat {
	return new(saferith.Nat).Mod(
		new(saferith.Nat).SetBytes(x), m,
	)
}

func NatRandomRangeLH(prng io.Reader, lowInclusive, highExclusive *saferith.Nat) (*saferith.Nat, error) {
	if lowInclusive == nil || highExclusive == nil || prng == nil {
		return nil, errs.NewIsNil("lowInclusive, highExclusive and prng must not be nil")
	}
	maxVal := new(saferith.Nat).Sub(highExclusive, lowInclusive, highExclusive.AnnouncedLen())
	if maxVal.EqZero() == 1 {
		return nil, errs.NewArgument("max must be greater than zero")
	}

	randInt, err := crand.Int(prng, maxVal.Big())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to get random")
	}
	return new(saferith.Nat).Add(lowInclusive, new(saferith.Nat).SetBig(randInt, highExclusive.AnnouncedLen()), highExclusive.AnnouncedLen()), nil
}

func NatRandomRangeH(prng io.Reader, highExclusive *saferith.Nat) (*saferith.Nat, error) {
	if highExclusive == nil || prng == nil {
		return nil, errs.NewIsNil("highExclusive and prng must not be nil")
	}
	randBig, err := crand.Int(prng, highExclusive.Big())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to get random")
	}
	return new(saferith.Nat).SetBig(randBig, highExclusive.AnnouncedLen()), nil
}

func NatRandomBits(prng io.Reader, bits uint) (*saferith.Nat, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng must not be nil")
	}
	randBytes := make([]byte, (bits+7)/8)
	_, err := io.ReadFull(prng, randBytes)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to get random")
	}
	return new(saferith.Nat).SetBytes(randBytes).Resize(int(bits)), nil
}

func NatGetBit(x *saferith.Nat, bit uint) uint {
	return x.Big().Bit(int(bit))
}

func NatSetBit(value *saferith.Nat, bit uint) *saferith.Nat {
	return new(saferith.Nat).SetBig(new(big.Int).SetBit(value.Big(), int(bit), 1), value.AnnouncedLen())
}

func NatIsLess(l, r *saferith.Nat) bool {
	_, _, less := l.Cmp(r)
	return less == 1
}

func NatIsOdd(x *saferith.Nat) bool {
	lsb := x.Byte(0)
	return lsb&0b1 == 1
}

func IntRandom(prng io.Reader, lowInclusive, highExclusive *saferith.Int) (*saferith.Int, error) {
	if lowInclusive == nil || highExclusive == nil {
		return nil, errs.NewIsNil("lowInclusive and highExclusive must not be nil")
	}
	if prng == nil {
		return nil, errs.NewIsNil("prng must not be nil")
	}
	intRange := new(saferith.Int).Add(highExclusive, lowInclusive.Clone().Neg(1), -1)
	if intRange.IsNegative() != 0 || lowInclusive.Eq(highExclusive) != 0 {
		return nil, errs.NewArgument("max must be greater than zero")
	}

	randBi, err := crand.Int(prng, intRange.Big())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to get random")
	}
	return new(saferith.Int).Add(lowInclusive, new(saferith.Int).SetBig(randBi, randBi.BitLen()), -1), nil
}

func Stringer[T BigIntAdapter](n T) string {
	return n.Big().String()
}
