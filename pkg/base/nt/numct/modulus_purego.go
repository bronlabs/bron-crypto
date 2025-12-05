//go:build purego || nobignum

package numct

import (
	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

// Modulus is a modulus implementation based on saferith.Modulus.
type Modulus = ModulusBasic

// NewModulus creates a new Modulus from a Nat.
func NewModulus(m *Nat) (modulus *Modulus, ok ct.Bool) {
	if m.IsZero() == ct.True { // saferith.ModulusFromNat panics on zero modulus
		return nil, ct.False
	}
	return (*ModulusBasic)(saferith.ModulusFromNat((*saferith.Nat)(m))), ct.True
}
