package damgard

import (
	"github.com/cronokirby/saferith"
)

type Shard struct {
	N  *saferith.Modulus
	E  uint64
	Di *saferith.Nat
}
