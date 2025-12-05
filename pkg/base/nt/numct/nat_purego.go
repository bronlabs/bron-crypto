//go:build purego || nobignum

package numct

import (
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct/internal"
	"github.com/cronokirby/saferith"
)

// GCD sets n = gcd(x, y) using a constant-time (w.r.t. announced capacity) binary GCD (Stein) algorithm.
// The result is always non-negative and gcd(0, 0) = 0.
func (n *Nat) GCD(x, y *Nat) {
	if x == nil || y == nil {
		panic("numct.Nat.GCD: nil input")
	}

	internal.GCD((*saferith.Nat)(n), (*saferith.Nat)(x), (*saferith.Nat)(y))
}
