package num

import (
	"io"
	"iter"
	"math/big"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

var (
	_             algebra.NPlusLike[*NatPlus]   = (*PositiveNaturalNumbers)(nil)
	_             algebra.NatPlusLike[*NatPlus] = (*NatPlus)(nil)
	nplusInstance *PositiveNaturalNumbers
	nplusOnce     sync.Once
)

type PositiveNaturalNumbers struct{}

func NPlus() *PositiveNaturalNumbers {
	nplusOnce.Do(func() {
		nplusInstance = &PositiveNaturalNumbers{}
	})
	return nplusInstance
}

func (*PositiveNaturalNumbers) Name() string {
	return "N+"
}

func (*PositiveNaturalNumbers) Characteristic() cardinal.Cardinal {
	return cardinal.Zero()
}

func (*PositiveNaturalNumbers) Order() cardinal.Cardinal {
	return cardinal.Infinite()
}

func (*PositiveNaturalNumbers) One() *NatPlus {
	return &NatPlus{v: numct.NatOne()}
}

func (*PositiveNaturalNumbers) FromCardinal(c algebra.Cardinal) (*NatPlus, error) {
	if c == nil {
		return nil, errs.NewValue("cardinal must not be nil")
	}
	if c.IsZero() {
		return nil, errs.NewValue("cardinal must be greater than 0")
	}
	return &NatPlus{v: numct.NewNatFromBytes(c.Bytes())}, nil
}

func (nps *PositiveNaturalNumbers) FromBig(b *big.Int) (*NatPlus, error) {
	if b == nil {
		return nil, errs.NewValue("big.Int must not be nil")
	}
	if b.Sign() <= 0 {
		return nil, errs.NewValue("big.Int must be greater than 0")
	}
	return nps.FromBytes(b.Bytes())
}

func (nps *PositiveNaturalNumbers) FromModulus(m *numct.Modulus) *NatPlus {
	return &NatPlus{v: m.Nat(), m: m}
}

func (nps *PositiveNaturalNumbers) FromRat(v *Rat) (*NatPlus, error) {
	vInt, err := Z().FromRat(v)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert Rat to Int")
	}
	return nps.FromInt(vInt)
}

func (*PositiveNaturalNumbers) FromUint64(value uint64) (*NatPlus, error) {
	if value == 0 {
		return nil, errs.NewValue("value must be greater than 0")
	}
	return &NatPlus{v: numct.NewNat(value)}, nil
}

func (*PositiveNaturalNumbers) FromNat(value *Nat) (*NatPlus, error) {
	if value == nil {
		return nil, errs.NewValue("value must not be nil")
	}
	if value.IsZero() {
		return nil, errs.NewValue("value must be greater than 0")
	}
	return &NatPlus{v: value.v.Clone()}, nil
}

func (*PositiveNaturalNumbers) FromNatCT(value *numct.Nat) (*NatPlus, error) {
	if value == nil {
		return nil, errs.NewValue("value must not be nil")
	}
	if value.IsZero() == ct.True {
		return nil, errs.NewValue("value must be greater than 0")
	}
	return &NatPlus{v: value.Clone()}, nil
}

func (*PositiveNaturalNumbers) FromInt(value *Int) (*NatPlus, error) {
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

func (*PositiveNaturalNumbers) FromBytes(input []byte) (*NatPlus, error) {
	if len(input) == 0 || ct.SliceIsZero(input) == ct.True {
		return nil, errs.NewValue("input must not be empty")
	}
	return &NatPlus{v: numct.NewNatFromBytes(input)}, nil
}

func (nps *PositiveNaturalNumbers) FromBytesBE(input []byte) (*NatPlus, error) {
	out, err := nps.FromBytes(input)
	if err != nil {
		return nil, errs.WrapArgument(err, "failed to create NatPlus from bytes BE")
	}
	if out.v.IsZero() == ct.True {
		return nil, errs.NewValue("input must represent a positive natural number")
	}
	return out, nil
}

func (nps *PositiveNaturalNumbers) Random(lowInclusive, highExclusive *NatPlus, prng io.Reader) (*NatPlus, error) {
	if highExclusive == nil {
		return nil, errs.NewIsNil("highExclusive must not be nil")
	}
	if lowInclusive == nil {
		lowInclusive = nps.Bottom()
	}
	var v numct.Nat
	if err := v.SetRandomRangeLH(lowInclusive.v, highExclusive.v, prng); err != nil {
		return nil, errs.WrapRandomSample(err, "failed to sample random NatPlus")
	}
	return &NatPlus{v: &v}, nil
}

func (nps *PositiveNaturalNumbers) Iter() iter.Seq[*NatPlus] {
	return nps.IterRange(nps.One(), nil)
}

func (nps *PositiveNaturalNumbers) OpIdentity() *NatPlus {
	return nps.One()
}

func (nps *PositiveNaturalNumbers) IterRange(start, stop *NatPlus) iter.Seq[*NatPlus] {
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

func (nps *PositiveNaturalNumbers) ElementSize() int {
	return 0
}

func (nps *PositiveNaturalNumbers) Bottom() *NatPlus {
	return nps.One()
}

type NatPlus struct {
	v *numct.Nat
	m *numct.Modulus
}

func (*NatPlus) isValid(x *NatPlus) (*NatPlus, error) {
	if x == nil {
		return nil, errs.NewValue("argument is nil")
	}
	if x.v.IsZero() == ct.True {
		return nil, errs.NewValue("argument is not a positive natural number")
	}
	return x, nil
}

func (*NatPlus) ensureValid(x *NatPlus) *NatPlus {
	// TODO: fix err package
	x, err := x.isValid(x)
	if err != nil {
		panic(err)
	}
	return x
}

func (np *NatPlus) cacheMont(m *numct.Modulus) *NatPlus {
	if np.m == nil {
		m, ok := numct.NewModulus(np.v)
		if ok == ct.False {
			panic(errs.NewFailed("modulus is not valid"))
		}
		np.m = m
	}
	return np
}

func (*NatPlus) Structure() algebra.Structure[*NatPlus] {
	return NPlus()
}

func (np *NatPlus) Value() *numct.Nat {
	return np.v
}

func (np *NatPlus) Op(other *NatPlus) *NatPlus {
	return np.Mul(other)
}

func (np *NatPlus) OtherOp(other *NatPlus) *NatPlus {
	return np.Add(other)
}

func (np *NatPlus) Add(other *NatPlus) *NatPlus {
	np.ensureValid(other)
	v := new(numct.Nat)
	v.Add(np.v, other.v)
	return np.ensureValid(&NatPlus{v: v, m: np.m})
}

func (np *NatPlus) Mul(other *NatPlus) *NatPlus {
	np.ensureValid(other)
	v := new(numct.Nat)
	v.Mul(np.v, other.v)
	out := &NatPlus{v: v, m: np.m}
	return np.ensureValid(out)
}

func (np *NatPlus) Lsh(shift uint) *NatPlus {
	v := new(numct.Nat)
	v.Lsh(np.v, shift)
	out := &NatPlus{v: v, m: np.m}
	return np.ensureValid(out)
}

func (np *NatPlus) Rsh(shift uint) *NatPlus {
	v := new(numct.Nat)
	v.Rsh(np.v, shift)
	out := &NatPlus{v: v, m: np.m}
	return np.ensureValid(out)
}

func (np *NatPlus) Double() *NatPlus {
	return np.Add(np)
}

func (np *NatPlus) Square() *NatPlus {
	return np.Mul(np)
}

func (np *NatPlus) IsOne() bool {
	return np.v.IsOne() == ct.True
}

func (np *NatPlus) IsOpIdentity() bool {
	return np.IsOne()
}

func (np *NatPlus) Compare(other *NatPlus) base.Ordering {
	np.ensureValid(other)
	lt, eq, gt := np.v.Compare(other.v)
	return base.Ordering(-1*int(lt) + 0*int(eq) + 1*int(gt))
}

func (np *NatPlus) TryInv() (*NatPlus, error) {
	return nil, errs.NewValue("no multiplicative inverse for NatPlus")
}

func (np *NatPlus) TryOpInv() (*NatPlus, error) {
	return np.TryInv()
}

func (np *NatPlus) TryDiv(other *NatPlus) (*NatPlus, error) {
	if _, err := np.isValid(other); err != nil {
		return nil, errs.WrapArgument(err, "argument is not valid")
	}
	v := new(numct.Nat)
	// Create modulus from divisor
	divisorMod, modOk := numct.NewModulus(other.v)
	if modOk != ct.True {
		return nil, errs.NewFailed("failed to create modulus from divisor")
	}
	// Use ExactDiv to ensure only exact division succeeds
	if ok := v.ExactDiv(np.v, divisorMod); ok != ct.True {
		return nil, errs.NewFailed("division is not exact")
	}
	out := &NatPlus{v: v, m: np.m}
	return np.isValid(out)
}

func (np *NatPlus) TrySub(other *NatPlus) (*NatPlus, error) {
	if _, err := np.isValid(other); err != nil {
		return nil, errs.WrapArgument(err, "argument is not valid")
	}
	if np.IsLessThanOrEqual(other) {
		return nil, errs.NewValue("result would not be a positive natural number")
	}
	v := new(numct.Nat)
	v.SubCap(np.v, other.v, -1)
	out := &NatPlus{v: v, m: np.m}
	return np.isValid(out)
}

func (np *NatPlus) IsLessThanOrEqual(other *NatPlus) bool {
	np.ensureValid(other)
	lt, eq, _ := np.v.Compare(other.v)
	return lt|eq == ct.True
}

func (np *NatPlus) IsUnit(modulus *NatPlus) bool {
	np.ensureValid(modulus)
	return np.v.Coprime(modulus.v) == ct.True
}

func (np *NatPlus) Equal(other *NatPlus) bool {
	np.ensureValid(other)
	return np.v.Equal(other.v) == ct.True
}

func (np *NatPlus) Mod(modulus *NatPlus) *Uint {
	return np.Lift().Mod(modulus)
}

func (np *NatPlus) Lift() *Int {
	return &Int{v: np.v.Lift()}
}

func (np *NatPlus) Clone() *NatPlus {
	return &NatPlus{v: np.v.Clone(), m: np.m}
}

func (np *NatPlus) HashCode() base.HashCode {
	return np.v.HashCode()
}

func (np *NatPlus) Abs() *NatPlus {
	return np.Clone()
}

func (np *NatPlus) String() string {
	return np.v.Big().String()
}

func (np *NatPlus) Increment() *NatPlus {
	return np.Add(NPlus().One())
}

func (np *NatPlus) Bytes() []byte {
	// Use Big().Bytes() to get compact representation without padding
	bytes := np.v.Big().Bytes()
	// big.Int.Bytes() returns empty slice for zero, but we want [0x0]
	// However, NatPlus should never be zero
	if len(bytes) == 0 {
		panic("NatPlus should never be zero")
	}
	return bytes
}

func (np *NatPlus) BytesBE() []byte {
	return np.Bytes()
}

func (np *NatPlus) IsBottom() bool {
	return np.IsOne()
}

func (np *NatPlus) Bit(i uint) byte {
	return np.v.Bit(i)
}

func (np *NatPlus) Byte(i uint) byte {
	return np.v.Byte(i)
}

func (np *NatPlus) IsEven() bool {
	return np.v.IsEven() == ct.True
}

func (np *NatPlus) IsOdd() bool {
	return np.v.IsOdd() == ct.True
}

func (np *NatPlus) Decrement() (*NatPlus, error) {
	if np.IsOne() {
		return nil, errs.NewValue("cannot decrement NatPlus below 1")
	}
	return np.TrySub(NPlus().One())
}

func (np *NatPlus) Big() *big.Int {
	return np.v.Big()
}

func (np *NatPlus) Cardinal() cardinal.Cardinal {
	return cardinal.NewFromSaferith((*saferith.Nat)(np.v))
}

func (np *NatPlus) Nat() *Nat {
	return &Nat{v: np.v.Clone()}
}

func (np *NatPlus) IsProbablyPrime() bool {
	return np.v.IsProbablyPrime() == ct.True
}

func (np *NatPlus) ModulusCT() *numct.Modulus {
	np.cacheMont(nil)
	return np.m
}

func (np *NatPlus) TrueLen() uint {
	return np.v.TrueLen()
}

func (np *NatPlus) AnnouncedLen() uint {
	return np.v.AnnouncedLen()
}
