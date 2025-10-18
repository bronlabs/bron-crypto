//go:build purego || nobignum

package numct

import (
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

type (
	ModulusOddPrime = ModulusOddPrimeBasic
	ModulusOdd      = ModulusOddBasic
	ModulusNonZero  = ModulusBasic
)

func NewModulusOddPrime(m *Nat) (*ModulusOddPrime, ct.Bool) {
	ok := m.IsNonZero() & m.IsOdd() & m.IsProbablyPrime()
	return newModulusOddPrimeBasic(m), ok
}

func NewModulusOdd(m *Nat) (*ModulusOdd, ct.Bool) {
	ok := m.IsNonZero() & m.IsOdd()
	return newModulusOddBasic(m), ok
}

func NewModulusNonZero(m *Nat) (*ModulusNonZero, ct.Bool) {
	ok := m.IsNonZero()
	return newModulusBasic(m), ok
}
