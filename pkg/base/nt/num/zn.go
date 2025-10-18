package num

import (
	"fmt"
	"io"
	"iter"
	"math/big"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/cronokirby/saferith"
	"golang.org/x/crypto/blake2b"
)

var (
// _ internal.ZModN[*Uint, *NatPlus, *Nat, *Int, *Uint] = (*ZMod)(nil)
// _ internal.Uint[*Uint, *NatPlus, *Nat, *Int, *Uint]  = (*Uint)(nil)
)

func NewZMod(modulus *NatPlus) (*ZMod, error) {
	if modulus == nil {
		return nil, errs.NewIsNil("modulus")
	}
	return &ZMod{n: modulus.cacheMont(nil)}, nil
}

func NewZModFromCardinal(n cardinal.Cardinal) (*ZMod, error) {
	nn, err := NPlus().FromCardinal(n)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create NatPlus from modulus cardinal")
	}
	nn.cacheMont(nil)
	return &ZMod{n: nn}, nil
}

func NewZModFromModulus(m numct.Modulus) (*ZMod, error) {
	if m.Nat() == nil {
		return nil, errs.NewIsNil("modulus Nat")
	}
	return &ZMod{n: NPlus().FromModulus(m)}, nil
}

func NewUintGivenModulus(value *numct.Nat, m numct.Modulus) (*Uint, error) {
	if m.Nat() == nil {
		return nil, errs.NewIsNil("modulus Nat")
	}
	if value == nil {
		return nil, errs.NewIsNil("value")
	}
	// if m.IsInRange(value) == ct.False {
	// 	return nil, errs.NewValue("value is out of range for modulus")
	// }
	return &Uint{v: value.Clone(), m: m}, nil
}

type ZMod struct {
	n *NatPlus
}

func (zn *ZMod) Name() string {
	return fmt.Sprintf("Z\\%sZ", zn.n.String())
}

func (zn *ZMod) Order() cardinal.Cardinal {
	return zn.n.Cardinal()
}

func (zn *ZMod) Characteristic() cardinal.Cardinal {
	return zn.n.Cardinal()
}

func (zn *ZMod) Modulus() *NatPlus {
	return zn.n
}

func (zn *ZMod) ElementSize() int {
	return int(zn.n.AnnouncedLen())
}

func (zn *ZMod) WideElementSize() int {
	return 2 * zn.ElementSize()
}

func (zn *ZMod) Bottom() *Uint {
	return zn.Zero()
}

func (zn *ZMod) FromUint64(value uint64) (*Uint, error) {
	return zn.FromNat(N().FromUint64(value))
}

func (zn *ZMod) FromInt64(value int64) (*Uint, error) {
	return zn.FromInt(Z().FromInt64(value))
}

func (zn *ZMod) FromInt(v *Int) (*Uint, error) {
	if v == nil {
		return nil, errs.NewIsNil("argument")
	}
	return v.Mod(zn.n), nil
}

func (zn *ZMod) FromBytes(input []byte) (*Uint, error) {
	v, err := N().FromBytes(input)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to deserialize Nat from bytes")
	}
	return zn.FromNat(v)
}

func (zn *ZMod) FromNat(v *Nat) (*Uint, error) {
	if v == nil {
		return nil, errs.NewIsNil("nat")
	}
	return v.Mod(zn.n), nil
}

func (zn *ZMod) FromNatCT(v *numct.Nat) (*Uint, error) {
	if v == nil {
		return nil, errs.NewIsNil("natct")
	}
	return (&Nat{v: v}).Mod(zn.n), nil
}

func (zn *ZMod) FromNatCTReduced(reducedV *numct.Nat) (*Uint, error) {
	if reducedV == nil {
		return nil, errs.NewIsNil("natct")
	}
	return &Uint{v: reducedV.Clone(), m: zn.n.m}, nil
}

func (zn *ZMod) FromNatPlus(v *NatPlus) (*Uint, error) {
	if v == nil {
		return nil, errs.NewIsNil("natplus")
	}
	return v.Mod(zn.n), nil
}

func (zn *ZMod) FromCardinal(v cardinal.Cardinal) (*Uint, error) {
	return zn.FromBytes(v.Bytes())
}

func (zn *ZMod) OpIdentity() *Uint {
	return zn.Zero()
}

func (zn *ZMod) Zero() *Uint {
	return &Uint{v: numct.NatZero(), m: zn.n.m}
}

func (zn *ZMod) One() *Uint {
	return &Uint{v: numct.NatOne(), m: zn.n.m}
}

func (zn *ZMod) Top() *Uint {
	out, err := zn.n.Decrement()
	if err != nil {
		panic(err)
	}
	return &Uint{v: out.v, m: zn.n.m}
}

func (zn *ZMod) Random(prng io.Reader) (*Uint, error) {
	out, err := numct.NatRandomRangeH(prng, zn.n.m.Nat())
	if err != nil {
		return nil, errs.WrapRandomSample(err, "failed to sample random element in Zn")
	}
	return &Uint{v: out, m: zn.n.m}, nil
}

func (zn *ZMod) Hash(input []byte) (*Uint, error) {
	xof, err := blake2b.NewXOF(uint32(zn.WideElementSize()), nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create blake2b XOF")
	}
	xof.Write(input)
	digest := make([]byte, zn.WideElementSize())
	if _, err = io.ReadFull(xof, digest); err != nil {
		return nil, errs.WrapSerialisation(err, "failed to read full blake2b XOF output")
	}
	x := new(numct.Nat)
	if ok := x.SetBytes(digest[:]); ok == ct.False {
		return nil, errs.NewSerialisation("failed to interpret hash digest as Nat")
	}
	v := new(numct.Nat)
	// Perform modular reduction using the modulus from n
	zn.n.m.Mod(v, x)
	return &Uint{v: v, m: zn.n.m}, nil
}

func (zn *ZMod) IsInRange(v *Nat) bool {
	if v == nil {
		panic(errs.NewIsNil("argument"))
	}
	return zn.n.m.IsInRange(v.v) == ct.True
}

func (zn *ZMod) Iter() iter.Seq[*Uint] {
	return zn.IterRange(nil, nil)
}

func (zn *ZMod) IterRange(start, stop *Uint) iter.Seq[*Uint] {
	return func(yield func(*Uint) bool) {
		if start == nil {
			start = zn.Zero()
		}
		if stop == nil {
			stop = zn.Top()
		}
		if !start.EqualModulus(stop) || start.Compare(stop).Is(base.GreaterThan) {
			return
		}
		cursor := start.Clone()
		for !cursor.Equal(stop) {
			if !yield(cursor) {
				return
			}
			cursor = cursor.Increment()
		}
	}
}

func (zn *ZMod) MultiScalarOp(scs []*Nat, es []*Uint) (*Uint, error) {
	return zn.MultiScalarExp(scs, es)
}

func (zn *ZMod) MultiScalarExp(scs []*Nat, es []*Uint) (*Uint, error) {
	if len(scs) != len(es) {
		return nil, errs.NewLength("scalars and exponents must have the same length")
	}
	if len(scs) == 0 {
		return nil, errs.NewLength("no scalars provided")
	}

	out := zn.One()
	for i, sc := range scs {
		if sc == nil || es[i] == nil {
			return nil, errs.NewIsNil("scalar or exponent is nil")
		}
		out = out.Mul(es[i].Exp(sc))
	}
	return out, nil
}

func (zn *ZMod) IsSemiDomain() bool {
	return zn.Modulus().Lift().IsProbablyPrime()
}

func (zn *ZMod) ScalarStructure() algebra.Structure[*Nat] {
	return N()
}

func (zn *ZMod) AmbientStructure() algebra.Structure[*Int] {
	return Z()
}

type Uint struct {
	v *numct.Nat
	m numct.Modulus
}

func (u *Uint) isValid(x *Uint) (*Uint, error) {
	if x == nil {
		return nil, errs.NewValue("argument is nil")
	}
	if x.m.Nat().Equal(u.m.Nat()) == ct.False {
		return nil, errs.NewValue("argument is not in the same modulus")
	}
	return x, nil
}

func (u *Uint) ensureValid(x *Uint) *Uint {
	// TODO: fix err package
	x, err := u.isValid(x)
	if err != nil {
		panic(err)
	}
	return x
}

func (u *Uint) Group() *ZMod {
	return &ZMod{
		n: NPlus().FromModulus(u.m),
	}
}

func (u *Uint) Value() *numct.Nat {
	return u.v
}

func (u *Uint) Structure() algebra.Structure[*Uint] {
	return u.Group()
}

func (u *Uint) Op(other *Uint) *Uint {
	return u.Add(other)
}

func (u *Uint) OtherOp(other *Uint) *Uint {
	return u.Mul(other)
}

func (u *Uint) IsNegative() bool {
	return false
}

func (u *Uint) TryOpInv() (*Uint, error) {
	return u.OpInv(), nil
}

func (u *Uint) OpInv() *Uint {
	return u.Neg()
}

func (u *Uint) IsPositive() bool {
	return u.v.IsNonZero() == ct.True
}

func (u *Uint) Add(other *Uint) *Uint {
	u.ensureValid(other)
	v := new(numct.Nat)
	u.m.ModAdd(v, u.v, other.v)
	return &Uint{v: v, m: u.m}
}

func (u *Uint) TrySub(other *Uint) (*Uint, error) {
	return u.Sub(other), nil
}

func (u *Uint) Sub(other *Uint) *Uint {
	u.ensureValid(other)
	v := new(numct.Nat)
	u.m.ModSub(v, u.v, other.v)
	return &Uint{v: v, m: u.m}
}

func (u *Uint) Mul(other *Uint) *Uint {
	u.ensureValid(other)
	v := new(numct.Nat)
	u.m.ModMul(v, u.v, other.v)
	return &Uint{v: v, m: u.m}
}

func (u *Uint) Lsh(shift uint) *Uint {
	return u.Lift().Lsh(shift).Mod(NPlus().FromModulus(u.m))
}

func (u *Uint) Rsh(shift uint) *Uint {
	return u.Lift().Rsh(shift).Mod(NPlus().FromModulus(u.m))
}

func (u *Uint) Exp(exponent *Nat) *Uint {
	if exponent == nil {
		panic(errs.NewIsNil("argument is nil"))
	}
	v := new(numct.Nat)
	u.m.ModExp(v, u.v, exponent.v)
	return &Uint{v: v, m: u.m}
}

func (u *Uint) ExpI(exponent *Int) *Uint {
	if exponent == nil {
		panic(errs.NewIsNil("argument is nil"))
	}
	v := new(numct.Nat)
	u.m.ModExpInt(v, u.v, exponent.v)
	return &Uint{v: v, m: u.m}
}

func (u *Uint) IsUnit() bool {
	return u.m.IsUnit(u.v) == ct.True
}

func (u *Uint) Coprime(other *Uint) bool {
	u.ensureValid(other)
	return u.v.Coprime(other.v) == ct.True
}

func (u *Uint) IsProbablyPrime() bool {
	return u.v.IsProbablyPrime() == ct.True
}

func (u *Uint) EuclideanDiv(other *Uint) (quot, rem *Uint, err error) {
	u.ensureValid(other)
	if !u.Group().IsSemiDomain() {
		return nil, nil, errs.NewFailed("not a euclidean domain")
	}
	vq, vr := new(numct.Nat), new(numct.Nat)
	// Create modulus from divisor
	divisorMod, modOk := numct.NewModulus(other.v)
	if modOk != ct.True {
		return nil, nil, errs.NewFailed("failed to create modulus from divisor")
	}
	if ok := numct.DivModCap(vq, vr, u.v, divisorMod, -1); ok == ct.False {
		return nil, nil, errs.NewFailed("division failed")
	}
	u.m.Mod(vq, vq)
	u.m.Mod(vr, vr)
	return &Uint{v: vq, m: u.m}, &Uint{v: vr, m: u.m}, nil
}

func (u *Uint) EuclideanValuation() *Uint {
	if !u.Group().IsSemiDomain() {
		panic(errs.NewType("not a euclidean domain"))
	}
	return u.Clone()
}

func (u *Uint) TryNeg() (*Uint, error) {
	return u.Neg(), nil
}

func (u *Uint) TryInv() (*Uint, error) {
	if !u.IsUnit() {
		return nil, errs.NewFailed("not a unit")
	}
	v := new(numct.Nat)
	u.m.ModInv(v, u.v)
	return &Uint{v: v, m: u.m}, nil
}

func (u *Uint) TryDiv(other *Uint) (*Uint, error) {
	u.ensureValid(other)
	v := new(numct.Nat)
	if ok := u.m.ModDiv(v, u.v, other.v); ok == ct.False {
		return nil, errs.NewFailed("division failed")
	}
	return &Uint{v: v, m: u.m}, nil
}

func (u *Uint) Double() *Uint {
	return u.Add(u)
}

func (u *Uint) Square() *Uint {
	return u.Mul(u)
}

func (u *Uint) IsOpIdentity() bool {
	return u.IsZero()
}

func (u *Uint) IsZero() bool {
	return u.v.IsZero() == ct.True
}

func (u *Uint) IsOne() bool {
	return u.v.IsOne() == ct.True
}

func (u *Uint) IsBottom() bool {
	return u.IsOne()
}

func (u *Uint) IsTop() bool {
	v := u.m.Nat()
	v.Decrement()
	return u.v.Equal(v) == ct.True
}

func (u *Uint) PartialCompare(other *Uint) base.PartialOrdering {
	// Check if other is nil first
	if other == nil {
		return base.Incomparable
	}
	// Check if they have the same modulus
	comparability := u.m.Nat().Equal(other.m.Nat())
	if comparability == ct.False {
		return base.Incomparable
	}
	// If they have the same modulus, compare values
	lt, eq, gt := u.v.Compare(other.v)
	return base.PartialOrdering(-1*int(lt) + 0*int(eq) + 1*int(gt))
}

func (u *Uint) Compare(other *Uint) base.Ordering {
	u.ensureValid(other)
	lt, eq, gt := u.v.Compare(other.v)
	return base.Ordering(-1*int(lt) + 0*int(eq) + 1*int(gt))
}

func (u *Uint) IsLessThanOrEqual(other *Uint) bool {
	u.ensureValid(other)
	lt, eq, _ := u.v.Compare(other.v)
	return lt|eq == ct.True
}

func (u *Uint) EqualModulus(other *Uint) bool {
	_, err := u.isValid(other)
	return err == nil
}

func (u *Uint) Equal(other *Uint) bool {
	_, err := u.isValid(other)
	return err == nil && u.v.Equal(other.v) == ct.True
}

func (u *Uint) IsQuadraticResidue() bool {
	panic("implement me")
}

func (u *Uint) Sqrt() (*Uint, error) {
	v := new(numct.Nat)
	if ok := u.m.ModSqrt(v, u.v); ok == ct.False {
		return nil, errs.NewFailed("square root failed")
	}
	return &Uint{v: v, m: u.m}, nil
}

func (u *Uint) Neg() *Uint {
	v := new(numct.Nat)
	u.m.ModNeg(v, u.v)
	return &Uint{v: v, m: u.m}
}

func (u *Uint) ScalarOp(other *Nat) *Uint {
	return u.ScalarExp(other)
}

func (u *Uint) IsTorsionFree() bool {
	return true
}

func (u *Uint) ScalarMul(other *Nat) *Uint {
	out, err := u.Group().FromNat(u.Nat().Mul(other))
	if err != nil {
		panic(err)
	}
	return out
}

func (u *Uint) ScalarExp(other *Nat) *Uint {
	return u.Exp(other)
}

func (u *Uint) Cardinal() cardinal.Cardinal {
	return cardinal.NewFromSaferith((*saferith.Nat)(u.v))
}

func (u *Uint) Clone() *Uint {
	return &Uint{u.v.Clone(), u.m}
}

func (u *Uint) Lift() *Int {
	out, err := Z().FromUint(u)
	if err != nil {
		panic(err)
	}
	return out
}

func (u *Uint) HashCode() base.HashCode {
	return base.HashCode(u.v.Uint64() % u.m.Nat().Uint64())
}

func (u *Uint) Modulus() *NatPlus {
	out := &NatPlus{v: u.m.Nat(), m: u.m}
	return out
}

func (u *Uint) ModulusCT() numct.Modulus {
	return u.m
}

func (u *Uint) String() string {
	return u.v.Big().String()
}

func (u *Uint) Increment() *Uint {
	return u.Add(u.Group().One())
}

func (u *Uint) Decrement() *Uint {
	return u.Sub(u.Group().One())
}

func (u *Uint) Bytes() []byte {
	return u.v.Bytes()
}

func (u *Uint) Bit(i uint) byte {
	return u.v.Bit(i)
}

func (u *Uint) IsEven() bool {
	return u.v.IsEven() == ct.True
}

func (u *Uint) IsOdd() bool {
	return u.v.IsOdd() == ct.True
}

func (u *Uint) Abs() *Nat {
	return &Nat{v: u.v.Clone()}
}

func (u *Uint) Nat() *Nat {
	return &Nat{v: u.v.Clone()}
}

func (u *Uint) Big() *big.Int {
	return u.v.Big()
}

func (u *Uint) TrueLen() uint {
	return u.v.TrueLen()
}

func (u *Uint) AnnouncedLen() uint {
	return u.v.AnnouncedLen()
}

func (u *Uint) Select(choice ct.Choice, x0, x1 *Uint) {
	u.v.Select(choice&x0.m.Nat().Equal(x1.m.Nat()), x0.v, x1.v)
	u.m = x0.m
}

func (u *Uint) CondAssign(choice ct.Choice, x *Uint) {
	u.v.CondAssign(choice, x.v)
	u.m = x.m
}
