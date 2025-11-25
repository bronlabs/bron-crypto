//go:build purego || nobignum

package numct

import (
	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

// Modulus is a modulus implementation based on saferith.Modulus.
type Modulus = ModulusBasic

// NewModulus creates a new Modulus from a Nat.
func NewModulus(m *Nat) (*Modulus, ct.Bool) {
	ok := m.IsNonZero()
	return (*ModulusBasic)(saferith.ModulusFromNat((*saferith.Nat)(m))), ok
}
