package cardinal

import (
	"fmt"
	"math/big"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base"
	acrtp "github.com/bronlabs/bron-crypto/pkg/base/algebra/crtp"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	saferith_utils "github.com/bronlabs/bron-crypto/pkg/base/utils/saferith"
)

type Cardinal = acrtp.Cardinal

var (
	zero Cardinal = &cardinal{
		v:         new(saferith.Nat).SetUint64(0),
		isUnknown: false,
		isFinite:  true,
	}
	infinite Cardinal = &cardinal{
		v:         nil,
		isUnknown: false,
		isFinite:  false,
	}
	unknown Cardinal = &cardinal{
		v:         nil,
		isUnknown: true,
		isFinite:  false,
	}
)

func Zero() Cardinal {
	return zero.Clone()
}

func Infinite() Cardinal {
	return infinite.Clone()
}

func Unknown() Cardinal {
	return unknown.Clone()
}

func New(n uint64) Cardinal {
	if n == 0 {
		return zero
	}
	return &cardinal{
		v:         new(saferith.Nat).SetUint64(n),
		isUnknown: false,
		isFinite:  true,
	}
}

func NewFromSaferith(n *saferith.Nat) Cardinal {
	if n == nil {
		return unknown
	}
	return &cardinal{
		v:         n,
		isUnknown: false,
		isFinite:  true,
	}
}

func NewFromBig(n *big.Int) Cardinal {
	if n == nil {
		return unknown
	}
	if n.Sign() < 0 {
		return zero // Negative values are not valid for cardinal numbers
	}
	if n.IsUint64() {
		return New(n.Uint64())
	}
	return &cardinal{
		v:         new(saferith.Nat).SetBig(n, -1),
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
	if c == nil || c.isUnknown || !c.isFinite || c.v == nil {
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
	o := other.(*cardinal)

	// Special case: Unknown == Unknown
	if c.isUnknown && o.isUnknown {
		return false
	}

	// Special case: Infinite == Infinite
	if c.IsInfinite() || o.IsInfinite() {
		return false
	}

	// Otherwise use the comparison logic
	return c.IsLessThanOrEqual(other) && other.IsLessThanOrEqual(c)
}

func (c *cardinal) IsFinite() bool {
	return c.isFinite
}

func (c *cardinal) IsUnknown() bool {
	return c.isUnknown
}

func (c *cardinal) IsInfinite() bool {
	return !c.isFinite && !c.isUnknown
}

func (c *cardinal) Add(other Cardinal) Cardinal {
	// Cast other to *cardinal assuming safe usage or precondition checked
	o := other.(*cardinal)

	if c.isUnknown || o.isUnknown {
		return unknown
	}

	if c.IsInfinite() || o.IsInfinite() {
		return infinite
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
		return unknown
	}

	if c.IsInfinite() || o.IsInfinite() {
		return infinite
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
		return unknown
	}

	if c.IsInfinite() || o.IsInfinite() {
		return infinite
	}

	if saferith_utils.NatIsLess(c.v, o.v) {
		return zero
	}
	out := new(saferith.Nat).Sub(c.v, o.v, -1)
	return &cardinal{
		v:         out,
		isUnknown: false,
		isFinite:  true,
	}
}

func (c *cardinal) IsZero() bool {
	if c == nil || c.v == nil || c.isUnknown || !c.isFinite {
		return false
	}
	return c.v.EqZero() == 1
}

func (c *cardinal) Bytes() []byte {
	if c == nil || c.isUnknown || !c.isFinite {
		return nil
	}
	return c.v.Bytes()
}

func (c *cardinal) Big() *big.Int {
	if c == nil || c.isUnknown || !c.isFinite {
		return nil
	}
	if c.v == nil {
		return big.NewInt(0)
	}
	return c.v.Big()
}

func (c *cardinal) Clone() Cardinal {
	if c == nil {
		return nil
	}
	var clonedV *saferith.Nat
	if c.v != nil {
		clonedV = c.v.Clone()
	}
	return &cardinal{
		v:         clonedV,
		isUnknown: c.isUnknown,
		isFinite:  c.isFinite,
	}
}

func (c *cardinal) HashCode() base.HashCode {
	if c == nil || c.isUnknown || !c.isFinite || c.v == nil {
		return base.HashCode(0)
	}
	return base.HashCode(c.v.Uint64())
}

func (c *cardinal) BitLen() uint {
	return uint(c.v.TrueLen())
}

func (c *cardinal) String() string {
	if c == nil {
		return "Nil"
	}
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
