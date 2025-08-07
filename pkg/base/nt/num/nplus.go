package num

// import (
// 	"io"
// 	"iter"
// 	"sync"

// 	"github.com/bronlabs/bron-crypto/pkg/base"
// 	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
// 	"github.com/bronlabs/bron-crypto/pkg/base/errs"
// 	"github.com/bronlabs/bron-crypto/pkg/ase/nt/cardinal"
// 	saferith_utils "github.com/bronlabs/bron-crypto/pkg/base/utils/saferith"
// 	"github.com/cronokirby/saferith"
// )

// var (
// 	_ algebra.NPlusLike[*NatPlus]   = (*PositiveNaturalNumbers)(nil)
// 	_ algebra.NatPlusLike[*NatPlus] = (*NatPlus)(nil)

// 	zero = new(saferith.Nat).SetUint64(0)
// 	one  = new(saferith.Nat).SetUint64(1)

// 	nplusInstance *PositiveNaturalNumbers
// 	nplusOnce     sync.Once
// )

// type PositiveNaturalNumbers struct{}

// func NPlus() *PositiveNaturalNumbers {
// 	nplusOnce.Do(func() {
// 		nplusInstance = &PositiveNaturalNumbers{}
// 	})
// 	return nplusInstance
// }

// func (*PositiveNaturalNumbers) Name() string {
// 	return "N+"
// }

// func (*PositiveNaturalNumbers) Characteristic() cardinal.Cardinal {
// 	return cardinal.Zero
// }

// func (*PositiveNaturalNumbers) Order() cardinal.Cardinal {
// 	return cardinal.Infinite
// }

// func (*PositiveNaturalNumbers) One() *NatPlus {
// 	return &NatPlus{v: *one}
// }

// func (*PositiveNaturalNumbers) FromUint64(value uint64) (*NatPlus, error) {
// 	if value == 0 {
// 		return nil, errs.NewValue("value must be greater than 0")
// 	}
// 	return &NatPlus{v: *new(saferith.Nat).SetUint64(value)}, nil
// }

// func (*PositiveNaturalNumbers) FromNat(value *Nat) (*NatPlus, error) {
// 	if value == nil {
// 		return nil, errs.NewValue("value must not be nil")
// 	}
// 	if value.IsZero() {
// 		return nil, errs.NewValue("value must be greater than 0")
// 	}
// 	return &NatPlus{v: *new(saferith.Nat).SetNat(&value.v)}, nil
// }

// func (*PositiveNaturalNumbers) FromInt(value *Int) (*NatPlus, error) {
// 	if value == nil {
// 		return nil, errs.NewValue("value must not be nil")
// 	}
// 	if value.IsZero() {
// 		return nil, errs.NewValue("value must be greater than 0")
// 	}
// 	if value.IsNegative() {
// 		return nil, errs.NewValue("value must be positive")
// 	}
// 	return &NatPlus{v: value.Abs().v}, nil
// }

// func (*PositiveNaturalNumbers) FromBytes(input []byte) (*NatPlus, error) {
// 	if len(input) == 0 {
// 		return nil, errs.NewValue("input must not be empty")
// 	}
// 	n := new(saferith.Nat).SetBytes(input)
// 	if n.Eq(zero) == 1 {
// 		return nil, errs.NewValue("value must be greater than 0")
// 	}
// 	return &NatPlus{v: *n}, nil
// }

// func (nps *PositiveNaturalNumbers) Random(lowInclusive, highExclusive *NatPlus, prng io.Reader) (*Nat, error) {
// 	if highExclusive == nil || prng == nil {
// 		return nil, errs.NewIsNil("highExclusive and prng must not be nil")
// 	}
// 	if lowInclusive == nil {
// 		lowInclusive = nps.One()
// 	}
// 	out, err := saferith_utils.NatRandomRangeLH(prng, &lowInclusive.v, &highExclusive.v)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return &Nat{v: *out}, nil
// }

// func (nps *PositiveNaturalNumbers) Iter() iter.Seq[*NatPlus] {
// 	return nps.IterRange(nps.One(), nil)
// }

// func (nps *PositiveNaturalNumbers) OpIdentity() *NatPlus {
// 	return nps.One()
// }

// func (nps *PositiveNaturalNumbers) IterRange(start, stop *NatPlus) iter.Seq[*NatPlus] {
// 	return func(yield func(*NatPlus) bool) {
// 		if start == nil {
// 			start = nps.One()
// 		}
// 		cursor := start.Clone()
// 		if stop == nil {
// 			for {
// 				if !yield(cursor) {
// 					return
// 				}
// 				cursor = cursor.Increment()
// 			}
// 		}
// 		if start.Compare(stop) == base.GreaterThan {
// 			return
// 		}
// 		for !cursor.Equal(stop) {
// 			if !yield(cursor) {
// 				return
// 			}
// 			cursor = cursor.Increment()
// 		}
// 	}
// }

// func (nps *PositiveNaturalNumbers) ElementSize() int {
// 	return 0
// }

// type NatPlus struct {
// 	v saferith.Nat
// }

// func (np *NatPlus) Structure() algebra.Structure[*NatPlus] {
// 	return NPlus()
// }

// func (np *NatPlus) Op(other *NatPlus) *NatPlus {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	return np.Add(other)
// }

// func (np *NatPlus) OtherOp(other *NatPlus) *NatPlus {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	return np.Mul(other)
// }

// func (np *NatPlus) Add(other *NatPlus) *NatPlus {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	out := new(saferith.Nat).Add(&np.v, &other.v, -1)
// 	return &NatPlus{v: *out}
// }

// func (np *NatPlus) Mul(other *NatPlus) *NatPlus {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	out := new(saferith.Nat).Mul(&np.v, &other.v, -1)
// 	return &NatPlus{v: *out}
// }

// func (np *NatPlus) Double() *NatPlus {
// 	return np.Add(np)
// }

// func (np *NatPlus) Square() *NatPlus {
// 	return np.Mul(np)
// }

// func (np *NatPlus) IsOne() bool {
// 	return np.v.Eq(one) == 1
// }

// func (np *NatPlus) IsOpIdentity() bool {
// 	return np.v.Eq(one) == 1
// }

// func (np *NatPlus) Compare(other *NatPlus) base.Ordering {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	gt, eq, lt := np.v.Cmp(&other.v)
// 	return base.Ordering(-1*int(lt) + 0*int(eq) + 1*int(gt))
// }

// func (np *NatPlus) TryInv() (*NatPlus, error) {
// 	return nil, errs.NewValue("no multiplicative inverse for NatPlus")
// }

// func (np *NatPlus) TryOpInv() (*NatPlus, error) {
// 	return np.TryInv()
// }

// func (np *NatPlus) TryDiv(other *NatPlus) (*NatPlus, error) {
// 	quot, err := np.Lift().TryDiv(other.Lift())
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "division failed")
// 	}
// 	return &NatPlus{v: quot.Abs().v}, nil
// }

// func (np *NatPlus) IsLessThanOrEqual(other *NatPlus) bool {
// 	return np.Compare(other) != base.GreaterThan
// }

// func (np *NatPlus) Equal(other *NatPlus) bool {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	return np.v.Eq(&other.v) == 1
// }

// func (np *NatPlus) Mod(modulus *NatPlus) *Uint {
// 	return np.Lift().Mod(modulus)
// }

// func (np *NatPlus) Lift() *Int {
// 	return &Int{v: *new(saferith.Int).SetNat(&np.v)}
// }

// func (np *NatPlus) Clone() *NatPlus {
// 	return &NatPlus{v: *np.v.Clone()}
// }

// func (np *NatPlus) HashCode() base.HashCode {
// 	return base.HashCode(np.v.Uint64())
// }

// func (np *NatPlus) String() string {
// 	return saferith_utils.Stringer(&np.v)
// }

// func (np *NatPlus) Increment() *NatPlus {
// 	return np.Add(NPlus().One())
// }

// func (np *NatPlus) Bytes() []byte {
// 	return np.v.Bytes()
// }

// func (np *NatPlus) Bit(i int) uint8 {
// 	return np.v.Byte(i)
// }

// func (np *NatPlus) IsEven() bool {
// 	return np.Bit(0) == 0
// }

// func (np *NatPlus) IsOdd() bool {
// 	return np.Bit(0) == 1
// }
// func (np *NatPlus) TrueLen() int {
// 	return np.v.TrueLen()
// }

// func (np *NatPlus) AnnouncedLen() int {
// 	return np.v.AnnouncedLen()
// }
