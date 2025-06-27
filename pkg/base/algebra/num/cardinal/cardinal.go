package cardinal

import (
	"fmt"

	aimpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	saferith_utils "github.com/bronlabs/bron-crypto/pkg/base/utils/saferith"
	"github.com/cronokirby/saferith"
)

type Cardinal = aimpl.Cardinal

var (
	Zero Cardinal = &cardinal{
		v:         new(saferith.Nat).SetUint64(0),
		isUnknown: false,
		isFinite:  true,
	}
	Infinite Cardinal = &cardinal{
		v:         nil,
		isUnknown: false,
		isFinite:  false,
	}
	Unknown Cardinal = &cardinal{
		v:         nil,
		isUnknown: true,
		isFinite:  false,
	}
)

func New(n uint64) Cardinal {
	if n == 0 {
		return Zero
	}
	return &cardinal{
		v:         new(saferith.Nat).SetUint64(n),
		isUnknown: false,
		isFinite:  true,
	}
}

func FromNat(n *saferith.Nat) Cardinal {
	if n == nil {
		return Unknown
	}
	return &cardinal{
		v:         n,
		isUnknown: false,
		isFinite:  true,
	}
}

type cardinal struct {
	v         *saferith.Nat
	isUnknown bool
	isFinite  bool
}

func (c *cardinal) IsProbablyPrime() bool {
	if c == nil || c.isUnknown || !c.isFinite {
		return false
	}
	return c.v.Big().ProbablyPrime(0)
}

func (c *cardinal) Uint64() uint64 {
	if c.isUnknown || !c.isFinite {
		return 0
	}
	if c.v == nil {
		return 0
	}
	return c.v.Uint64()
}

func (c *cardinal) IsLessThanOrEqual(other Cardinal) bool {
	o := other.(*cardinal)

	// Avoid nil dereference (v might be nil if isUnknown or !isFinite)
	// We'll use a default dummy saferith.Nat with value 0
	dummy := new(saferith.Nat)

	v1 := c.v
	v2 := o.v

	// If v1 or v2 is nil, use dummy instead to avoid panic
	if v1 == nil {
		v1 = dummy
	}
	if v2 == nil {
		v2 = dummy
	}

	// Evaluate flags in constant time
	isUnknown1 := utils.BoolTo[saferith.Choice](c.isUnknown)
	isUnknown2 := utils.BoolTo[saferith.Choice](o.isUnknown)
	isFinite1 := utils.BoolTo[saferith.Choice](c.isFinite)
	isFinite2 := utils.BoolTo[saferith.Choice](o.isFinite)

	// Cmp still runs but operates on dummy if v=nil
	_, eq, lt := v1.Cmp(v2)
	le := eq | lt // 1 if v1 ≤ v2

	// knownMask = 1 iff both finite and neither unknown
	knownMask := ^(isUnknown1 | isUnknown2) & isFinite1 & isFinite2

	// Apply mask in constant time
	return (knownMask & le) == 1
}

func (c *cardinal) Equal(other Cardinal) bool {
	return c.IsLessThanOrEqual(other) && other.IsLessThanOrEqual(c)
}

func (c *cardinal) IsFinite() bool {
	return c.isFinite
}

func (c *cardinal) IsUnknown() bool {
	return c.isUnknown
}

func (c *cardinal) Add(other Cardinal) Cardinal {
	// Cast other to *cardinal assuming safe usage or precondition checked
	o := other.(*cardinal)

	if c.isUnknown || o.isUnknown {
		return Unknown
	}

	if !c.isFinite || !o.isFinite {
		return Infinite
	}

	out := new(saferith.Nat).Add(c.v, o.v, -1)
	return &cardinal{
		v:         out,
		isUnknown: false,
		isFinite:  true,
	}
}

func (c *cardinal) Mul(other Cardinal) Cardinal {
	// Cast other to *cardinal assuming safe usage or precondition checked
	o := other.(*cardinal)

	if c.isUnknown || o.isUnknown {
		return Unknown
	}

	if !c.isFinite || !o.isFinite {
		return Infinite
	}

	out := new(saferith.Nat).Mul(c.v, o.v, -1)
	return &cardinal{
		v:         out,
		isUnknown: false,
		isFinite:  true,
	}
}

func (c *cardinal) Sub(other Cardinal) Cardinal {
	// Cast other to *cardinal assuming safe usage or precondition checked
	o := other.(*cardinal)

	if c.isUnknown || o.isUnknown {
		return Unknown
	}

	if !c.isFinite || !o.isFinite {
		return Infinite
	}

	if saferith_utils.NatIsLess(c.v, o.v) {
		return Zero
	}
	out := new(saferith.Nat).Sub(c.v, o.v, -1)
	return &cardinal{
		v:         out,
		isUnknown: false,
		isFinite:  true,
	}
}

func (c *cardinal) IsZero() bool {
	return c.Equal(Zero)
}

func (c *cardinal) Value() *saferith.Nat {
	if c.isUnknown || !c.isFinite {
		return nil
	}
	return c.v
}

func (c *cardinal) Bytes() []byte {
	if c.isUnknown || !c.isFinite {
		return nil
	}
	return c.v.Bytes()
}

func (c *cardinal) String() string {
	if c.isUnknown {
		return "Unknown"
	}
	if !c.isFinite {
		return "Infinite"
	}
	if c.v == nil {
		return "Empty"
	}
	return fmt.Sprintf("Cardinal(%s)", c.v.Big().String())
}
