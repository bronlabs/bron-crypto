package uint128

import (
	"sync"

	"github.com/cronokirby/saferith"

	saferithUtils "github.com/bronlabs/krypton-primitives/pkg/base/utils/saferith"
)

const (
	Name      = "uint128"
	RingBits  = 128
	RingBytes = RingBits / 8
)

var (
	ring128InitOnce sync.Once
	ring128Instance *Ring128

	mod2Pow128 = saferith.ModulusFromNat(new(saferith.Nat).Lsh(saferithUtils.NatOne, RingBits, -1))
)

func ring128Init() {
	ring128Instance = &Ring128{}
}

func Ring() *Ring128 {
	ring128InitOnce.Do(ring128Init)
	return ring128Instance
}
