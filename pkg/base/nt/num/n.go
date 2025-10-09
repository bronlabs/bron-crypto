package num

import (
	"errors"
	"io"
	"iter"
	"math/big"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/internal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/cronokirby/saferith"
)

var (
	_ internal.N[*Nat, *NatPlus, *Nat, *Int, *Uint]   = (*NaturalNumbers)(nil)
	_ internal.Nat[*Nat, *NatPlus, *Nat, *Int, *Uint] = (*Nat)(nil)

	nOnce     sync.Once
	nInstance *NaturalNumbers
)

func N() *NaturalNumbers {
	nOnce.Do(func() {
		nInstance = &NaturalNumbers{}
	})
	return nInstance
}

type NaturalNumbers struct{}

func (*NaturalNumbers) Name() string {
	return "N"
}
func (*NaturalNumbers) Characteristic() cardinal.Cardinal {
	return cardinal.Zero()
}
func (*NaturalNumbers) Order() cardinal.Cardinal {
	return cardinal.Infinite()
}

func (*NaturalNumbers) Zero() *Nat {
	return &Nat{v: numct.NatZero()}
}

func (*NaturalNumbers) One() *Nat {
	return &Nat{v: numct.NatOne()}
}

func (ns *NaturalNumbers) OpIdentity() *Nat {
	return ns.Zero()
}

func (ns *NaturalNumbers) FromUint64(value uint64) *Nat {
	return &Nat{v: numct.NewNat(value)}
}

func (ns *NaturalNumbers) FromNatPlus(value *NatPlus) (*Nat, error) {
	if value == nil {
		return nil, errs.NewValue("value must not be nil")
	}
	return &Nat{v: value.v.Clone()}, nil
}

func (ns *NaturalNumbers) FromBig(value *big.Int) (*Nat, error) {
	if value == nil {
		return nil, errs.NewValue("value must not be nil")
	}
	if value.Sign() < 0 {
		return nil, errs.NewValue("value must be greater than or equal to 0")
	}
	if value.Sign() == 0 {
		return ns.Zero(), nil
	}
	return ns.FromBytes(value.Bytes())
}

func (ns *NaturalNumbers) FromNatCT(value *numct.Nat) (*Nat, error) {
	if value == nil {
		return nil, errs.NewValue("value must not be nil")
	}
	return &Nat{v: value.Clone()}, nil
}

func (ns *NaturalNumbers) FromInt(value *Int) (*Nat, error) {
	if value == nil {
		return nil, errs.NewValue("value must not be nil")
	}
	if value.IsNegative() {
		return nil, errs.NewValue("value must be greater than or equal to 0")
	}
	if value.IsZero() {
		return ns.Zero(), nil
	}
	return value.Abs(), nil
}

func (ns *NaturalNumbers) FromBytes(input []byte) (*Nat, error) {
	if input == nil {
		return nil, errs.NewValue("input must not be nil")
	}
	return &Nat{v: numct.NewNatFromBytes(input)}, nil
}

func (ns *NaturalNumbers) FromCardinal(value cardinal.Cardinal) (*Nat, error) {
	if value == nil {
		return nil, errs.NewValue("value must not be nil")
	}
	if value.IsZero() {
		return ns.Zero(), nil
	}
	return &Nat{v: numct.NewNatFromBytes(value.Bytes())}, nil
}

func (ns *NaturalNumbers) Random(lowInclusive, highExclusive *Nat, prng io.Reader) (*Nat, error) {
	if highExclusive == nil {
		return nil, errors.New("highExclusive must not be nil")
	}
	if lowInclusive == nil {
		lowInclusive = ns.Bottom()
	}
	v, err := numct.NatRandomRangeLH(prng, lowInclusive.v, highExclusive.v)
	if err != nil {
		return nil, err
	}
	return &Nat{v: v}, nil
}

func (ns *NaturalNumbers) Bottom() *Nat {
	return ns.Zero()
}

func (ns *NaturalNumbers) Iter() iter.Seq[*Nat] {
	return ns.IterRange(ns.Zero(), nil)
}

func (ns *NaturalNumbers) IterRange(start, stop *Nat) iter.Seq[*Nat] {
	return func(yield func(*Nat) bool) {
		if start == nil {
			start = ns.Zero()
		}
		cursor := start.Clone()
		if stop == nil {
			for {
				if !yield(cursor) {
					return
				}
				cursor = cursor.Increment()
			}
		}
		if start.Compare(stop).Is(base.GreaterThan) {
			return
		}
		for !cursor.Equal(stop) {
			if !yield(cursor) {
				return
			}
			cursor = cursor.Increment()
		}
	}
}

func (ns *NaturalNumbers) ElementSize() int {
	return 0
}

func (ns *NaturalNumbers) MultiScalarOp(scs []*Nat, es []*Nat) (*Nat, error) {
	return ns.MultiScalarMul(scs, es)
}

func (ns *NaturalNumbers) MultiScalarMul(scs []*Nat, es []*Nat) (*Nat, error) {
	if len(scs) != len(es) {
		return nil, errs.NewValue("#scalars != #elements")
	}
	out := ns.Zero()
	for i, s := range scs {
		out = out.Add(es[i].Mul(s))
	}
	return out, nil
}

func (ns *NaturalNumbers) ScalarStructure() algebra.Structure[*Nat] {
	return N()
}

type Nat struct {
	v *numct.Nat
}

func (*Nat) isValid(x *Nat) (*Nat, error) {
	if x == nil {
		return nil, errs.NewValue("argument is nil")
	}
	return x, nil
}

func (*Nat) ensureValid(x *Nat) *Nat {
	// TODO: fix err package
	x, err := x.isValid(x)
	if err != nil {
		panic(err)
	}
	return x
}

func (*Nat) Structure() algebra.Structure[*Nat] {
	return N()
}

func (n *Nat) Value() *numct.Nat {
	return n.v
}

func (n *Nat) Op(other *Nat) *Nat {
	return n.Add(other)
}

func (n *Nat) OtherOp(other *Nat) *Nat {
	return n.Mul(other)
}

func (n *Nat) Add(other *Nat) *Nat {
	n.ensureValid(other)
	v := new(numct.Nat)
	v.Add(n.v, other.v)
	return &Nat{v: v}
}

func (n *Nat) Mul(other *Nat) *Nat {
	n.ensureValid(other)
	v := new(numct.Nat)
	v.Mul(n.v, other.v)
	return &Nat{v: v}
}

func (n *Nat) Lsh(shift uint) *Nat {
	v := new(numct.Nat)
	v.Lsh(n.v, shift)
	return &Nat{v: v}
}

func (n *Nat) Rsh(shift uint) *Nat {
	v := new(numct.Nat)
	v.Rsh(n.v, shift)
	return &Nat{v: v}
}

func (n *Nat) TryOpInv() (*Nat, error) {
	return n.TryNeg()
}

func (n *Nat) TryNeg() (*Nat, error) {
	return nil, errs.NewValue("negation not defined for natural numbers")
}

func (n *Nat) TrySub(other *Nat) (*Nat, error) {
	if _, err := n.isValid(other); err != nil {
		return nil, errs.WrapArgument(err, "argument is not valid")
	}
	if n.Compare(other).Is(base.LessThan) {
		return nil, errs.NewValue("result would not be a natural number")
	}
	v := new(numct.Nat)
	v.SubCap(n.v, other.v, -1)
	return &Nat{v: v}, nil
}

func (n *Nat) TryInv() (*Nat, error) {
	return nil, errs.NewValue("no multiplicative inverse for nat")
}

func (n *Nat) IsUnit(modulus *NatPlus) bool {
	if modulus == nil {
		panic("argument is nil")
	}
	m, ok := numct.NewModulus(modulus.v)
	if ok == ct.False {
		panic(errs.NewFailed("modulus is not valid"))
	}
	return m.IsUnit(n.v) == ct.True
}

func (n *Nat) Cardinal() cardinal.Cardinal {
	return cardinal.NewFromSaferith((*saferith.Nat)(n.v))
}

func (n *Nat) TryDiv(other *Nat) (*Nat, error) {
	if _, err := n.isValid(other); err != nil {
		return nil, errs.WrapArgument(err, "argument is not valid")
	}
	v := new(numct.Nat)
	// Create modulus from divisor
	divisorMod, modOk := numct.NewModulus(other.v)
	if modOk != ct.True {
		return nil, errs.NewFailed("failed to create modulus from divisor")
	}
	// Use ExactDiv to ensure only exact division succeeds
	if ok := v.ExactDiv(n.v, divisorMod); ok != ct.True {
		return nil, errs.NewFailed("division is not exact")
	}
	out := &Nat{v: v}
	return n.isValid(out)
}

func (n *Nat) Double() *Nat {
	return n.Add(n)
}

func (n *Nat) IsPositive() bool {
	return !n.IsZero()
}

func (n *Nat) Square() *Nat {
	return n.Mul(n)
}

func (n *Nat) IsOpIdentity() bool {
	return n.IsZero()
}

func (n *Nat) IsBottom() bool {
	return n.v.IsZero() == ct.True
}

func (n *Nat) IsZero() bool {
	return n.v.IsZero() == ct.True
}

func (n *Nat) IsOne() bool {
	return n.v.IsOne() == ct.True
}

func (n *Nat) Coprime(other *Nat) bool {
	n.ensureValid(other)
	return n.v.Coprime(other.v) == ct.True
}

func (n *Nat) IsProbablyPrime() bool {
	return n.v.IsProbablyPrime() == ct.True
}

func (n *Nat) EuclideanDiv(other *Nat) (quot, rem *Nat, err error) {
	n.ensureValid(other)
	vq, vr := new(numct.Nat), new(numct.Nat)
	// Create modulus from divisor
	divisorMod, modOk := numct.NewModulus(other.v)
	if modOk != ct.True {
		return nil, nil, errs.NewFailed("failed to create modulus from divisor")
	}
	if ok := numct.DivModCap(vq, vr, n.v, divisorMod, -1); ok == ct.False {
		return nil, nil, errs.NewFailed("division failed")
	}
	return &Nat{v: vq}, &Nat{v: vr}, nil
}

func (n *Nat) EuclideanValuation() *Nat {
	return n.Clone()
}

func (n *Nat) Mod(modulus *NatPlus) *Uint {
	return n.Lift().Mod(modulus)
}

func (n *Nat) Compare(other *Nat) base.Ordering {
	n.ensureValid(other)
	lt, eq, gt := n.v.Compare(other.v)
	return base.Ordering(-1*int(lt) + 0*int(eq) + 1*int(gt))
}

func (n *Nat) IsLessThanOrEqual(other *Nat) bool {
	n.ensureValid(other)
	lt, eq, _ := n.v.Compare(other.v)
	return lt|eq == ct.True
}

func (n *Nat) Lift() *Int {
	return &Int{v: n.v.Lift()}
}

func (n *Nat) Equal(other *Nat) bool {
	n.ensureValid(other)
	return n.v.Equal(other.v) == ct.True
}

func (n *Nat) Clone() *Nat {
	return &Nat{v: n.v.Clone()}
}

func (n *Nat) HashCode() base.HashCode {
	return base.HashCode(n.v.Uint64())
}

func (n *Nat) String() string {
	return n.v.Big().String()
}

func (n *Nat) Increment() *Nat {
	return n.Add(N().One())
}

func (n *Nat) Decrement() (*Nat, error) {
	return n.TrySub(N().One())
}

func (n *Nat) Bytes() []byte {
	// Use Big().Bytes() to get compact representation without padding
	bytes := n.v.Big().Bytes()
	// big.Int.Bytes() returns empty slice for zero, but we want [0x0]
	if len(bytes) == 0 {
		return []byte{0x0}
	}
	return bytes
}

func (n *Nat) Uint64() uint64 {
	return n.v.Uint64()
}

func (n *Nat) Bit(i uint) byte {
	return n.v.Bit(i)
}

func (n *Nat) Byte(i uint) byte {
	return n.v.Byte(i)
}

func (n *Nat) IsEven() bool {
	return n.v.IsEven() == ct.True
}

func (n *Nat) IsOdd() bool {
	return n.v.IsOdd() == ct.True
}

func (n *Nat) Big() *big.Int {
	return n.v.Big()
}

func (n *Nat) IsTorsionFree() bool {
	return true
}

func (n *Nat) ScalarOp(sc *Nat) *Nat {
	return n.ScalarMul(sc)
}

func (n *Nat) ScalarMul(sc *Nat) *Nat {
	return n.Mul(sc)
}

func (n *Nat) TrueLen() uint {
	return n.v.TrueLen()
}

func (n *Nat) AnnouncedLen() uint {
	return n.v.AnnouncedLen()
}
