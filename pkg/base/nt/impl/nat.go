package impl

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/internal"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/cronokirby/saferith"
)

var (
	SafeNatTwo  = new(saferith.Nat).SetUint64(2).Resize(64)
	SafeNatOne  = new(saferith.Nat).SetUint64(1).Resize(1)
	SafeNatZero = new(saferith.Nat).SetUint64(0).Resize(1)

	_ (internal.NatMutable[*Nat]) = (*Nat)(nil)
)

func NewNat(value uint64) *Nat {
	n := new(Nat)
	n.SetUint64(value)
	return n
}

func NewNatSaferith(n *saferith.Nat) *Nat {
	return (*Nat)(n)
}

type Nat saferith.Nat

func (n *Nat) Set(v *Nat) {
	*n = *v
}

func (n *Nat) SetZero() {
	n.Set((*Nat)(SafeNatZero))
}

func (n *Nat) SetOne() {
	n.Set((*Nat)(SafeNatOne))
}

func (n *Nat) Clone() *Nat {
	return (*Nat)((*saferith.Nat)(n).Clone())
}

func (n *Nat) Add(lhs, rhs *Nat) {
	n.AddCap(lhs, rhs, -1)
}

func (n *Nat) AddCap(lhs, rhs *Nat, cap int) {
	self := (*saferith.Nat)(n)
	x := (*saferith.Nat)(lhs)
	y := (*saferith.Nat)(rhs)
	self.Add(x, y, cap)
}

func (n *Nat) SubCap(lhs, rhs *Nat, cap int) {
	self := (*saferith.Nat)(n)
	x := (*saferith.Nat)(lhs)
	y := (*saferith.Nat)(rhs)
	self.Sub(x, y, cap)
}

func (n *Nat) Mul(lhs, rhs *Nat) {
	n.MulCap(lhs, rhs, -1)
}

func (n *Nat) MulCap(lhs, rhs *Nat, cap int) {
	self := (*saferith.Nat)(n)
	x := (*saferith.Nat)(lhs)
	y := (*saferith.Nat)(rhs)
	self.Mul(x, y, cap)
}

func (n *Nat) DivCap(lhs, rhs *Nat, cap int) (ok ct.Bool) {
	ok = rhs.IsNonZero()
	effectiveDenominator := new(Nat)
	fallback := (*Nat)(new(saferith.Nat).SetUint64(2).Resize(64))
	effectiveDenominator.CondAssign(ok, fallback, rhs) // when ok=true, use rhs; when ok=false, use fallback

	safeModulus := saferith.ModulusFromNat((*saferith.Nat)(effectiveDenominator))

	quot := new(saferith.Nat).Div((*saferith.Nat)(lhs), safeModulus, cap)
	// For exact division check, use sufficient capacity for the product
	prodCap := cap
	if cap < 0 {
		prodCap = 256 // Use a reasonable default when cap is -1
	} else {
		prodCap = cap + safeModulus.BitLen()
	}
	ok &= ct.Choice(new(saferith.Nat).Mul((*saferith.Nat)(rhs), quot, prodCap).Eq((*saferith.Nat)(lhs))) // is exact
	n.CondAssign(ok, n, (*Nat)(quot))
	return ok
}

func (n *Nat) Mod(a, m *Nat) (ok ct.Bool) {
	ok = m.IsNonZero()

	effectiveModulus := new(Nat)
	fallback := (*Nat)(new(saferith.Nat).SetUint64(2).Resize(64))
	effectiveModulus.CondAssign(ok, fallback, m) // when ok=true, use m; when ok=false, use fallback

	safeModulus := saferith.ModulusFromNat((*saferith.Nat)(effectiveModulus))

	rem := (*Nat)(new(saferith.Nat).Mod((*saferith.Nat)(a), safeModulus))

	n.CondAssign(ok, n, rem)
	return ok
}

// DivModCap computes a / b and a % b, storing the results into outQuot and outRem.
// The cap parameter sets the announced capacity (in bits) for the quotient.
func (n *Nat) DivModCap(outQuot, outRem, a, b *Nat, cap algebra.Capacity) (ok ct.Bool) {
	ok = b.IsNonZero()

	effectiveDenominator := new(Nat)
	fallback := (*Nat)(new(saferith.Nat).SetUint64(2).Resize(64))
	effectiveDenominator.CondAssign(ok, fallback, b) // when ok=true, use b; when ok=false, use fallback

	safeModulus := saferith.ModulusFromNat((*saferith.Nat)(effectiveDenominator))

	quot := new(saferith.Nat).Div((*saferith.Nat)(a), safeModulus, cap)
	rem := new(saferith.Nat).Mod((*saferith.Nat)(a), safeModulus)

	outQuot.CondAssign(ok, outQuot, (*Nat)(quot))
	outRem.CondAssign(ok, outRem, (*Nat)(rem))
	return ok
}

func (n *Nat) Double(x *Nat) {
	n.Add(x, x)
}

func (n *Nat) Increment() {
	n.Add(n, (*Nat)(SafeNatOne))
}

func (n *Nat) Decrement() {
	self := (*saferith.Nat)(n)
	self.Sub(self, SafeNatOne, -1)
}

func (n *Nat) Bit(i uint) byte {
	b := (*saferith.Nat)(n).Byte(int(i / 8))
	return (b >> (i % 8)) & 1
}

func (n *Nat) Compare(rhs *Nat) (lt, eq, gt ct.Bool) {
	sgt, seq, slt := (*saferith.Nat)(n).Cmp((*saferith.Nat)(rhs))
	return ct.Bool(slt), ct.Bool(seq), ct.Bool(sgt)
}

func (n *Nat) Equal(rhs *Nat) ct.Bool {
	return ct.Bool((*saferith.Nat)(n).Eq((*saferith.Nat)(rhs)))
}

func (n *Nat) IsZero() ct.Bool {
	return ct.Bool((*saferith.Nat)(n).EqZero())
}

func (n *Nat) IsNonZero() ct.Bool {
	return n.IsZero().Not()
}

func (n *Nat) IsOne() ct.Bool {
	return ct.Bool((*saferith.Nat)(n).Eq(SafeNatOne))
}

func (n *Nat) Coprime(x *Nat) ct.Bool {
	return ct.Bool((*saferith.Nat)(n).Coprime((*saferith.Nat)(x)))
}

func (n *Nat) String() string {
	return (*saferith.Nat)(n).String()
}

func (n *Nat) TrueLen() uint {
	return uint((*saferith.Nat)(n).TrueLen())
}

func (n *Nat) AnnouncedLen() uint {
	return uint((*saferith.Nat)(n).AnnouncedLen())
}

func (n *Nat) CondAssign(choice ct.Choice, x0, x1 *Nat) {
	*n = *x0.Clone()
	(*saferith.Nat)(n).CondAssign(saferith.Choice(choice), (*saferith.Nat)(x1))
}

func (n *Nat) IsOdd() ct.Bool {
	return ct.Bool((*saferith.Nat)(n).Byte(0) & 0b1)
}

func (n *Nat) IsEven() ct.Bool {
	return n.IsOdd().Not()
}

func (n *Nat) Resize(cap algebra.Capacity) {
	(*saferith.Nat)(n).Resize(cap)
}

func (n *Nat) Lsh(x *Nat, shift uint) {
	n.LshCap(x, shift, -1)
}

func (n *Nat) IsProbablyPrime() ct.Bool {
	return utils.BoolTo[ct.Bool]((*saferith.Nat)(n).Big().ProbablyPrime(0))
}

func (n *Nat) LshCap(x *Nat, shift uint, cap int) {
	(*saferith.Nat)(n).Lsh((*saferith.Nat)(x), shift, cap)
}

func (n *Nat) Rsh(x *Nat, shift uint) {
	n.RshCap(x, shift, -1)
}

func (n *Nat) RshCap(x *Nat, shift uint, cap int) {
	(*saferith.Nat)(n).Rsh((*saferith.Nat)(x), shift, cap)
}

func (n *Nat) Uint64() uint64 {
	return (*saferith.Nat)(n).Uint64()
}

func (n *Nat) SetUint64(x uint64) {
	(*saferith.Nat)(n).SetUint64(x)
}

func (n *Nat) Bytes() []byte {
	return (*saferith.Nat)(n).Bytes()
}

func (n *Nat) SetBytes(data []byte) (ok ct.Bool) {
	(*saferith.Nat)(n).SetBytes(data)
	return ct.True
}
