package nat

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/bignat/nat"
	"github.com/cronokirby/saferith"
)

type SmodImpl saferith.Modulus

var _ nat.Modulus = (*SmodImpl)(nil)

func (s *SmodImpl) Nat() nat.Nat {
	return (*SnatImpl)(((*saferith.Modulus)(s)).Nat())
}
