package numct

import (
	crand "crypto/rand"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

// n must already be reduced mod p^k
func Vp(out *Nat, p Modulus, n *Nat, k int) int {
	temp := n.Clone()
	var quo, rem Nat
	m := 0
	for range k {
		p.Mod(&rem, temp)
		isDiv := rem.IsZero()
		p.Quo(&quo, temp)
		temp.Select(isDiv, temp, &quo)
		m += int(isDiv)
	}
	out.Set(temp) // u := a / p^m mod p^k
	return m
}

func NatRandomRangeLH(prng io.Reader, lowInclusive, highExclusive *Nat) (*Nat, error) {
	if lowInclusive == nil || highExclusive == nil || prng == nil {
		return nil, errs.NewIsNil("lowInclusive, highExclusive and prng must not be nil")
	}
	maxVal := new(Nat)
	maxVal.SubCap(highExclusive, lowInclusive, int(highExclusive.AnnouncedLen()))
	if maxVal.IsZero() == ct.True {
		return nil, errs.NewArgument("max must be greater than zero")
	}

	randBig, err := crand.Int(prng, maxVal.Big())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to get random")
	}

	out := new(Nat)
	out.AddCap(lowInclusive, NewNatFromBig(randBig, int(highExclusive.AnnouncedLen())), int(highExclusive.AnnouncedLen()))
	return out, nil
}

func NatRandomRangeH(prng io.Reader, highExclusive *Nat) (*Nat, error) {
	if highExclusive == nil || prng == nil {
		return nil, errs.NewIsNil("highExclusive and prng must not be nil")
	}
	randBig, err := crand.Int(prng, highExclusive.Big())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to get random")
	}
	return NewNatFromBig(randBig, int(highExclusive.AnnouncedLen())), nil
}

func NatRandomBits(prng io.Reader, bits uint) (*Nat, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng must not be nil")
	}
	randBytes := make([]byte, (bits+7)/8)
	_, err := io.ReadFull(prng, randBytes)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to get random")
	}
	out := NewNatFromBytes(randBytes)
	out.Resize(int(bits))
	return out, nil
}

func IntRandom(prng io.Reader, lowInclusive, highExclusive *Int) (*Int, error) {
	if lowInclusive == nil || highExclusive == nil {
		return nil, errs.NewIsNil("lowInclusive and highExclusive must not be nil")
	}
	if prng == nil {
		return nil, errs.NewIsNil("prng must not be nil")
	}
	intRange := new(Int)
	intRange.Sub(highExclusive, lowInclusive)
	if intRange.IsNegative() == ct.True || lowInclusive.Equal(highExclusive) == ct.True {
		return nil, errs.NewArgument("max must be greater than zero")
	}

	randBig, err := crand.Int(prng, intRange.Big())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to get random")
	}
	out := new(Int)
	out.Add(lowInclusive, NewIntFromBig(randBig, randBig.BitLen()))
	return out, nil
}
