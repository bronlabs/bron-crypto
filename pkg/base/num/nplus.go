package num

import (
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/cronokirby/saferith"
)

var (
	_ algebra.NPlusLike[*NatPlus]   = (*nPlus)(nil)
	_ algebra.NatPlusLike[*NatPlus] = (*NatPlus)(nil)

	zero = new(saferith.Nat).SetUint64(0)
	one  = new(saferith.Nat).SetUint64(1)

	NPlus = &nPlus{}
)

type nPlus struct{}

func (*nPlus) Name() string {
	return "N+"
}

func (*nPlus) Operator() algebra.BinaryOperator[*NatPlus] {
	return algebra.Add[*NatPlus]
}

func (*nPlus) OtherOperator() algebra.BinaryOperator[*NatPlus] {
	return algebra.Mul[*NatPlus]
}

func (*nPlus) Characteristic() algebra.Cardinal {
	return zero
}

func (*nPlus) Order() algebra.Cardinal {
	return algebra.Infinite
}

func (*nPlus) One() *NatPlus {
	return &NatPlus{v: *one}
}

func (*nPlus) FromUint64(value uint64) (*NatPlus, error) {
	if value == 0 {
		return nil, errs.NewValue("value must be greater than 0")
	}
	return &NatPlus{v: *new(saferith.Nat).SetUint64(value)}, nil
}

func (*nPlus) FromNat(value *Nat) (*NatPlus, error) {
	if value == nil {
		return nil, errs.NewValue("value must not be nil")
	}
	if value.IsZero() {
		return nil, errs.NewValue("value must be greater than 0")
	}
	return &NatPlus{v: *new(saferith.Nat).SetNat(&value.v)}, nil
}

func (*nPlus) FromInt(value *Int) (*NatPlus, error) {
	if value == nil {
		return nil, errs.NewValue("value must not be nil")
	}
	if value.IsZero() {
		return nil, errs.NewValue("value must be greater than 0")
	}
	if value.IsNegative() {
		return nil, errs.NewValue("value must be positive")
	}
	return &NatPlus{v: value.Abs().v}, nil
}

func (*nPlus) FromBytes(input []byte) (*NatPlus, error) {
	if len(input) == 0 {
		return nil, errs.NewValue("input must not be empty")
	}
	n := new(saferith.Nat).SetBytes(input)
	if n.Eq(zero) == 1 {
		return nil, errs.NewValue("value must be greater than 0")
	}
	return &NatPlus{v: *n}, nil
}

func (nps *nPlus) Iter() iter.Seq[*NatPlus] {
	return nps.IterRange(nps.One(), nil)
}

func (nps *nPlus) IterRange(start, stop *NatPlus) iter.Seq[*NatPlus] {
	return func(yield func(*NatPlus) bool) {
		if start == nil {
			start = nps.One()
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

type NatPlus struct {
	v saferith.Nat
}

func (np *NatPlus) Structure() algebra.Structure[*NatPlus] {
	return NPlus
}

func (np *NatPlus) Op(other *NatPlus) *NatPlus {
	if other == nil {
		panic("argument is nil")
	}
	return np.Add(other)
}

func (np *NatPlus) OtherOp(other *NatPlus) *NatPlus {
	if other == nil {
		panic("argument is nil")
	}
	return np.Mul(other)
}

func (np *NatPlus) Add(other *NatPlus) *NatPlus {
	if other == nil {
		panic("argument is nil")
	}
	out := new(saferith.Nat).Add(&np.v, &other.v, -1)
	return &NatPlus{v: *out}
}

func (np *NatPlus) Mul(other *NatPlus) *NatPlus {
	if other == nil {
		panic("argument is nil")
	}
	out := new(saferith.Nat).Mul(&np.v, &other.v, -1)
	return &NatPlus{v: *out}
}

func (np *NatPlus) Double() *NatPlus {
	return np.Add(np)
}

func (np *NatPlus) Square() *NatPlus {
	return np.Mul(np)
}

func (np *NatPlus) IsOne() bool {
	return np.v.Eq(one) == 1
}

func (np *NatPlus) Compare(other *NatPlus) algebra.Ordering {
	if other == nil {
		panic("argument is nil")
	}
	gt, eq, lt := np.v.Cmp(&other.v)
	return algebra.Ordering(-1*int(lt) + 0*int(eq) + 1*int(gt))
}

func (np *NatPlus) IsLessThanOrEqual(other *NatPlus) bool {
	return np.Compare(other) != algebra.GreaterThan
}

func (np *NatPlus) Equal(other *NatPlus) bool {
	if other == nil {
		panic("argument is nil")
	}
	return np.v.Eq(&other.v) == 1
}

func (np *NatPlus) Mod(modulus *NatPlus) *Uint {
	return np.Lift().Mod(modulus)
}

func (np *NatPlus) Lift() *Int {
	return &Int{v: *new(saferith.Int).SetNat(&np.v)}
}

func (np *NatPlus) Clone() *NatPlus {
	return &NatPlus{v: *np.v.Clone()}
}

func (np *NatPlus) HashCode() uint64 {
	return np.v.Uint64()
}

func (np *NatPlus) String() string {
	return np.v.String()
}

func (np *NatPlus) Increment() *NatPlus {
	return np.Add(NPlus.One())
}

func (np *NatPlus) Bytes() []byte {
	return np.v.Bytes()
}

func (np *NatPlus) Bit(i int) uint8 {
	return np.v.Byte(i)
}

func (np *NatPlus) IsEven() bool {
	return np.Bit(0) == 0
}

func (np *NatPlus) IsOdd() bool {
	return np.Bit(0) == 1
}
func (np *NatPlus) TrueLen() int {
	return np.v.TrueLen()
}

func (np *NatPlus) AnnouncedLen() int {
	return np.v.AnnouncedLen()
}

func (np *NatPlus) MarshalBinary() ([]byte, error) {
	panic("implement me")
}

func (np *NatPlus) UnmarshalBinary(input []byte) error {
	panic("implement me")
}
