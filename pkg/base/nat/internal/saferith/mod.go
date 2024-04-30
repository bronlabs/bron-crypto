package saferith

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/nat"
	"github.com/cronokirby/saferith"
)

type SMod saferith.Modulus

var _ nat.Modulus = (*SMod)(nil)

func (s *SMod) Nat() nat.Nat {
	return (*SNat)(((*saferith.Modulus)(s)).Nat())
}
