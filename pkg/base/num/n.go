package num

import (
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/cronokirby/saferith"
)

var (
	_ algebra.NLike[*Nat]   = (*nats)(nil)
	_ algebra.NatLike[*Nat] = (*Nat)(nil)

	N = &nats{}
)

type nats struct{}

func (*nats) Name() string {
	return "N"
}
func (*nats) Operator() algebra.BinaryOperator[*Nat] {
	return algebra.Add[*Nat]
}
func (*nats) OtherOperator() algebra.BinaryOperator[*Nat] {
	return algebra.Mul[*Nat]
}
func (*nats) Characteristic() algebra.Cardinal {
	return zero
}
func (*nats) Order() algebra.Cardinal {
	return algebra.Infinite
}

func (*nats) Zero() *Nat {
	return &Nat{v: *zero}
}

func (*nats) One() *Nat {
	return &Nat{v: *one}
}

func (ns *nats) OpIdentity() *Nat {
	return ns.Zero()
}

func (ns *nats) FromUint64(value uint64) *Nat {
	return &Nat{v: *new(saferith.Nat).SetUint64(value)}
}

func (ns *nats) FromInt(value *Int) (*Nat, error) {
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

func (ns *nats) FromBytes(input []byte) (*Nat, error) {
	if input == nil {
		return nil, errs.NewValue("input must not be nil")
	}
	n := new(saferith.Nat).SetBytes(input)
	return &Nat{v: *n}, nil
}

func (ns *nats) Iter() iter.Seq[*Nat] {
	return ns.IterRange(ns.Zero(), nil)
}

func (ns *nats) IterRange(start, stop *Nat) iter.Seq[*Nat] {
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
		if start.Compare(stop) == algebra.GreaterThan {
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

type Nat struct {
	v saferith.Nat
}

func (n *Nat) Structure() algebra.Structure[*Nat] {
	return &nats{}
}

func (n *Nat) Op(other *Nat) *Nat {
	if other == nil {
		panic("argument is nil")
	}
	return n.Add(other)
}

func (n *Nat) OtherOp(other *Nat) *Nat {
	if other == nil {
		panic("argument is nil")
	}
	return n.Mul(other)
}

func (n *Nat) Add(other *Nat) *Nat {
	if other == nil {
		panic("argument is nil")
	}
	out := new(saferith.Nat).Add(&n.v, &other.v, -1)
	return &Nat{v: *out}
}

func (n *Nat) Mul(other *Nat) *Nat {
	if other == nil {
		panic("argument is nil")
	}
	out := new(saferith.Nat).Mul(&n.v, &other.v, -1)
	return &Nat{v: *out}
}

func (n *Nat) TryOpInv() (*Nat, error) {
	return nil, errs.NewValue("no additive inverse for nat")
}

func (n *Nat) TryNeg() (*Nat, error) {
	return nil, errs.NewValue("negation not defined for natural numbers")
}

func (n *Nat) TrySub(other *Nat) (*Nat, error) {
	if other == nil {
		panic("argument is nil")
	}
	if !other.IsLessThanOrEqual(n) {
		return nil, errs.NewValue("subtraction would result in negative number")
	}
	out := new(saferith.Nat).Sub(&n.v, &other.v, -1)
	return &Nat{v: *out}, nil
}

func (n *Nat) TryInv() (*Nat, error) {
	return nil, errs.NewValue("no multiplicative inverse for nat")
}

func (n *Nat) IsUnit(modulus *NatPlus) bool {
	if modulus == nil {
		panic("argument is nil")
	}
	m := saferith.ModulusFromNat(&modulus.v)
	return n.v.IsUnit(m) == 1
}

func (n *Nat) TryDiv(other *Nat) (*Nat, error) {
	if other == nil {
		panic("argument is nil")
	}
	quot, rem, err := n.EuclideanDiv(other)
	if err != nil {
		return nil, errs.WrapFailed(err, "division failed")
	}
	if !rem.IsZero() {
		return nil, errs.NewValue("division not exact")
	}
	return quot, nil
}

func (n *Nat) Double() *Nat {
	return n.Add(n)
}

func (n *Nat) Square() *Nat {
	return n.Mul(n)
}

func (n *Nat) IsOpIdentity() bool {
	return n.IsZero()
}

func (n *Nat) IsZero() bool {
	return n.v.Eq(zero) == 1
}

func (n *Nat) IsOne() bool {
	return n.v.Eq(one) == 1
}

func (n *Nat) Coprime(other *Nat) bool {
	if other == nil {
		panic("argument is nil")
	}
	return n.v.Coprime(&other.v) == 1
}

func (n *Nat) IsProbablyPrime() bool {
	return n.v.Big().ProbablyPrime(0)
}

func (n *Nat) EuclideanDiv(other *Nat) (quot, rem *Nat, err error) {
	if other == nil {
		panic("argument is nil")
	}
	if other.IsZero() {
		return nil, nil, errs.NewValue("division by zero")
	}

	q := new(saferith.Nat).Div(&n.v, saferith.ModulusFromNat(&other.v), -1)
	integerPart := new(saferith.Nat).Mul(q, &other.v, -1)
	r := new(saferith.Nat).Sub(&n.v, integerPart, -1)

	return &Nat{v: *q}, &Nat{v: *r}, nil
}

func (n *Nat) Mod(modulus *NatPlus) *Uint {
	return n.Lift().Mod(modulus)
}

func (n *Nat) Compare(other *Nat) algebra.Ordering {
	if other == nil {
		panic("argument is nil")
	}
	gt, eq, lt := n.v.Cmp(&other.v)
	return algebra.Ordering(-1*int64(lt) + 0*int64(eq) + 1*int64(gt))
}

func (n *Nat) IsLessThanOrEqual(other *Nat) bool {
	return n.Compare(other) != algebra.GreaterThan
}

func (n *Nat) Lift() *Int {
	return &Int{v: *new(saferith.Int).SetNat(&n.v)}
}

func (n *Nat) Equal(other *Nat) bool {
	if other == nil {
		panic("argument is nil")
	}
	return n.v.Eq(&other.v) == 1
}

func (n *Nat) Clone() *Nat {
	return &Nat{v: *n.v.Clone()}
}

func (n *Nat) HashCode() uint64 {
	return n.v.Uint64()
}

func (n *Nat) String() string {
	return n.v.String()
}

func (n *Nat) Increment() *Nat {
	return n.Add(N.One())
}

func (n *Nat) Bytes() []byte {
	return n.v.Bytes()
}

func (n *Nat) Bit(i int) uint8 {
	return n.v.Byte(i)
}

func (n *Nat) IsEven() bool {
	return n.Bit(0) == 0
}

func (n *Nat) IsOdd() bool {
	return n.Bit(0) == 1
}

func (n *Nat) TrueLen() int {
	return n.v.TrueLen()
}

func (n *Nat) AnnouncedLen() int {
	return n.v.AnnouncedLen()
}

func (n *Nat) MarshalBinary() ([]byte, error) {
	panic("implement me")
}

func (n *Nat) UnmarshalBinary(input []byte) error {
	panic("implement me")
}
