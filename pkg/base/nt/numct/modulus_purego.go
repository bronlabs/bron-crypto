//go:build purego || nobignum

package numct

import (
	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

type Modulus = ModulusBasic

func NewModulus(m *Nat) (*Modulus, ct.Bool) {
	ok := m.IsNonZero()
	return (*ModulusBasic)(saferith.ModulusFromNat((*saferith.Nat)(m))), ok
}
