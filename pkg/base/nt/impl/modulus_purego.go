//go:build purego || nobignum

package impl

import (
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

type (
	ModulusOddPrime = ModulusOddPrimeBasic
	ModulusOdd      = ModulusOddBasic
	Modulus         = ModulusBasic
)

func NewModulusOddPrime(m *Nat) (*ModulusOddPrime, ct.Bool) {
	ok := m.IsNonZero() & m.IsOdd() & m.IsProbablyPrime()
	return newModulusOddPrimeBasic(m), ok
}

func NewModulusOdd(m *Nat) (*ModulusOdd, ct.Bool) {
	ok := m.IsNonZero() & m.IsOdd()
	return newModulusOddBasic(m), ok
}

func NewModulus(m *Nat) (*Modulus, ct.Bool) {
	ok := m.IsNonZero()
	return newModulusBasic(m), ok
}
