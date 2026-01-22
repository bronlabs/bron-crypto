package num

import (
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/blake2b"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

// NewZMod creates a new ZMod structure given a modulus NatPlus.
func NewZMod(modulus *NatPlus) (*ZMod, error) {
	if modulus == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	return &ZMod{n: modulus.cacheMont(nil)}, nil
}

// NewZModFromCardinal creates a new ZMod structure given a cardinal.
func NewZModFromCardinal(n cardinal.Cardinal) (*ZMod, error) {
	nn, err := NPlus().FromCardinal(n)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	nn.cacheMont(nil)
	return &ZMod{n: nn}, nil
}

// NewZModFromModulus creates a new ZMod structure given a modulus Modulus.
func NewZModFromModulus(m *numct.Modulus) (*ZMod, error) {
	if m.Nat() == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	return &ZMod{n: NPlus().FromModulusCT(m)}, nil
}

// NewUintGivenModulus creates a new Uint element given a value Nat and a modulus Modulus.
func NewUintGivenModulus(value *numct.Nat, m *numct.Modulus) (*Uint, error) {
	if m.Nat() == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	if value == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	if m.IsInRange(value) == ct.False {
		return nil, ErrOutOfRange.WithStackFrame()
	}
	return &Uint{v: value.Clone(), m: m}, nil
}

// ZMod represents the integers modulo n.
type ZMod struct {
	n *NatPlus
}

// Name returns the name of the structure.
func (zn *ZMod) Name() string {
	return fmt.Sprintf("Z\\%sZ", zn.n.String())
}

// Order returns the order of the group.
func (zn *ZMod) Order() cardinal.Cardinal {
	return zn.n.Cardinal()
}

// Characteristic returns the characteristic of the group.
func (zn *ZMod) Characteristic() cardinal.Cardinal {
	return zn.n.Cardinal()
}

// Modulus returns the modulus NatPlus of the group.
func (zn *ZMod) Modulus() *NatPlus {
	return zn.n
}

func (zn *ZMod) ModulusCT() *numct.Modulus {
	return zn.n.ModulusCT()
}

// ElementSize returns the size in bytes of an element.
func (zn *ZMod) ElementSize() int {
	return zn.n.AnnouncedLen()
}

// WideElementSize returns the size in bytes of a wide element.
func (zn *ZMod) WideElementSize() int {
	return 2 * zn.ElementSize()
}

// Bottom returns the bottom element of the group.
func (zn *ZMod) Bottom() *Uint {
	return zn.Zero()
}

// FromUint64 creates a Uint element from a uint64 value.
func (zn *ZMod) FromUint64(value uint64) *Uint {
	return errs.Must1(zn.FromNat(N().FromUint64(value)))
}

// FromInt64 creates a Uint element from an int64 value.
func (zn *ZMod) FromInt64(value int64) (*Uint, error) {
	return zn.FromInt(Z().FromInt64(value))
}

// FromInt creates a Uint element from an Int value.
// It will reduce the Int modulo the modulus of the ZMod.
func (zn *ZMod) FromInt(v *Int) (*Uint, error) {
	if v == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	return v.Mod(zn.n), nil
}

// FromRat creates a Uint element from a Rat value.
// It will reduce the Rat modulo the modulus of the ZMod.
func (zn *ZMod) FromRat(v *Rat) (*Uint, error) {
	vInt, err := Z().FromRat(v)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return zn.FromInt(vInt)
}

// FromBytes creates a Uint element from a byte slice.
// It will NOT reduce the value modulo the modulus, and will return an error if the value is out of range.
func (zn *ZMod) FromBytes(input []byte) (*Uint, error) {
	v, err := N().FromBytes(input)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return zn.FromNatCTReduced(v.Value())
}

// FromBytesBE creates a Uint element from a big-endian byte slice.
// It will NOT reduce the value modulo the modulus, and will return an error if the value is out of range.
func (zn *ZMod) FromBytesBE(input []byte) (*Uint, error) {
	return zn.FromBytes(input)
}

// FromBytesBEReduce creates a Uint element from a big-endian byte slice, reducing it modulo the modulus.
// It will reduce the value modulo the modulus of the ZMod.
func (zn *ZMod) FromBytesBEReduce(input []byte) (*Uint, error) {
	v, err := N().FromBytes(input)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return zn.FromNatCT(v.Value())
}

// FromNat creates a Uint element from a Nat value.
// It will reduce the value modulo the modulus of the ZMod.
func (zn *ZMod) FromNat(v *Nat) (*Uint, error) {
	if v == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	return v.Mod(zn.n), nil
}

// FromNatCT creates a Uint element from a numct.Nat value.
// It will reduce the value modulo the modulus.
func (zn *ZMod) FromNatCT(v *numct.Nat) (*Uint, error) {
	if v == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	return (&Nat{v: v}).Mod(zn.n), nil
}

// FromNatCTReduced creates a Uint element from a reduced numct.Nat value.
// It will NOT reduce the value modulo the modulus, and will return an error if the value is out of range.
func (zn *ZMod) FromNatCTReduced(reducedV *numct.Nat) (*Uint, error) {
	if reducedV == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	if zn.n.m.IsInRange(reducedV) == ct.False {
		return nil, ErrOutOfRange.WithStackFrame()
	}
	return &Uint{v: reducedV.Clone(), m: zn.n.m}, nil
}

// FromNatPlus creates a Uint element from a NatPlus value.
// It will reduce the value modulo the modulus of the ZMod.
func (zn *ZMod) FromNatPlus(v *NatPlus) (*Uint, error) {
	if v == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	return v.Mod(zn.n), nil
}

// FromCardinal creates a Uint element from a cardinal.
// It will NOT reduce the value modulo the modulus, and will return an error if the value is out of range.
func (zn *ZMod) FromCardinal(v cardinal.Cardinal) (*Uint, error) {
	return zn.FromBytes(v.Bytes())
}

// FromBig creates a Uint element from a big.Int value.
// It will reduce the value modulo the modulus of the ZMod.
func (zn *ZMod) FromBig(v *big.Int) (*Uint, error) {
	if v == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	z, err := Z().FromBig(v)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return zn.FromInt(z)
}

// OpIdentity returns the additive identity element of the group.
func (zn *ZMod) OpIdentity() *Uint {
	return zn.Zero()
}

// Zero returns the zero element of the group.
func (zn *ZMod) Zero() *Uint {
	return &Uint{v: numct.NatZero(), m: zn.n.m}
}

// One returns the one element of the group.
func (zn *ZMod) One() *Uint {
	return &Uint{v: numct.NatOne(), m: zn.n.m}
}

// Top returns the top element of the group.
func (zn *ZMod) Top() *Uint {
	out, err := zn.n.Decrement()
	if err != nil {
		panic(err)
	}
	return &Uint{v: out.v, m: zn.n.m}
}

// Random samples a random element from the group using the provided PRNG.
func (zn *ZMod) Random(prng io.Reader) (*Uint, error) {
	out, err := zn.n.m.Random(prng)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return &Uint{v: out, m: zn.n.m}, nil
}

// Hash hashes the input byte slice to an element of the group.
func (zn *ZMod) Hash(input []byte) (*Uint, error) {
	xof, err := blake2b.NewXOF(uint32(zn.WideElementSize()), nil)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	if _, err := xof.Write(input); err != nil {
		return nil, errs.Wrap(err)
	}
	digest := make([]byte, zn.WideElementSize())
	if _, err = io.ReadFull(xof, digest); err != nil {
		return nil, errs.Wrap(err)
	}
	x := new(numct.Nat)
	if ok := x.SetBytes(digest); ok == ct.False {
		return nil, errs.New("failed to interpret hash digest as Nat")
	}
	v := new(numct.Nat)
	// Perform modular reduction using the modulus from n
	zn.n.m.Mod(v, x)
	return &Uint{v: v, m: zn.n.m}, nil
}

// IsInRange checks if a Nat value is in the range of the group.
func (zn *ZMod) IsInRange(v *Nat) bool {
	if v == nil {
		panic(ErrIsNil.WithStackFrame())
	}
	return zn.n.m.IsInRange(v.v) == ct.True
}

// IsDomain checks if the group is a domain (i.e., if the modulus is probably prime).
func (zn *ZMod) IsDomain() bool {
	return zn.Modulus().Lift().IsProbablyPrime()
}

// ScalarStructure returns the scalar structure of the group.
func (*ZMod) ScalarStructure() algebra.Structure[*Nat] {
	return N()
}

// AmbientStructure returns the ambient structure of quotient group ie. Z.
func (*ZMod) AmbientStructure() algebra.Structure[*Int] { //nolint:staticcheck // false positive.
	return Z()
}

// Uint represents an integer modulo n.
type Uint struct {
	v *numct.Nat
	m *numct.Modulus
}

func (u *Uint) isValid(x *Uint) (*Uint, error) {
	if x == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	if x.m.Nat().Equal(u.m.Nat()) == ct.False {
		return nil, ErrUnequalModuli.WithStackFrame()
	}
	return x, nil
}

// Group returns the ZMod structure that this Uint belongs to.
func (u *Uint) Group() *ZMod {
	return &ZMod{
		n: NPlus().FromModulusCT(u.m),
	}
}

// Value returns the underlying numct.Nat value of the Uint.
func (u *Uint) Value() *numct.Nat {
	return u.v
}

// Structure returns the algebraic structure of the Uint.
func (u *Uint) Structure() algebra.Structure[*Uint] {
	return u.Group()
}

// Op performs the group operation (addition) on two Uint elements.
func (u *Uint) Op(other *Uint) *Uint {
	return u.Add(other)
}

// OtherOp performs the other group operation (multiplication) on two Uint elements.
func (u *Uint) OtherOp(other *Uint) *Uint {
	return u.Mul(other)
}

// IsNegative checks the Uint would have been wrapped around if interpreted as an element of in [-n/2, n/2).
func (u *Uint) IsNegative() bool {
	return !u.Lift().IsLessThanOrEqual(u.Modulus().Increment().Rsh(1).Lift())
}

// TryOpInv returns the additive inverse of the Uint element.
func (u *Uint) TryOpInv() (*Uint, error) {
	return u.OpInv(), nil
}

// OpInv returns the additive inverse of the Uint element.
func (u *Uint) OpInv() *Uint {
	return u.Neg()
}

// IsPositive checks if the Uint is non-zero.
func (u *Uint) IsPositive() bool {
	return u.v.IsNonZero() == ct.True
}

// Add performs addition of two Uint elements.
func (u *Uint) Add(other *Uint) *Uint {
	errs.Must1(u.isValid(other))
	v := new(numct.Nat)
	u.m.ModAdd(v, u.v, other.v)
	return &Uint{v: v, m: u.m}
}

// TrySub performs subtraction of two Uint elements.
func (u *Uint) TrySub(other *Uint) (*Uint, error) {
	return u.Sub(other), nil
}

// Sub performs subtraction of two Uint elements.
func (u *Uint) Sub(other *Uint) *Uint {
	errs.Must1(u.isValid(other))
	v := new(numct.Nat)
	u.m.ModSub(v, u.v, other.v)
	return &Uint{v: v, m: u.m}
}

// Mul performs multiplication of two Uint elements.
func (u *Uint) Mul(other *Uint) *Uint {
	errs.Must1(u.isValid(other))
	v := new(numct.Nat)
	u.m.ModMul(v, u.v, other.v)
	return &Uint{v: v, m: u.m}
}

// Lsh performs left shift on the Uint element.
// Lsh is equivalent to multiplying by 2^shift mod modulus.
func (u *Uint) Lsh(shift uint) *Uint {
	return u.Lift().Lsh(shift).Mod(NPlus().FromModulusCT(u.m))
}

// Rsh performs right shift on the Uint element.
// Rsh is equivalent to floor division by 2^shift, then mod modulus.
func (u *Uint) Rsh(shift uint) *Uint {
	return u.Lift().Rsh(shift).Mod(NPlus().FromModulusCT(u.m))
}

// Exp performs exponentiation of the Uint element by a Nat exponent.
func (u *Uint) Exp(exponent *Nat) *Uint {
	if exponent == nil {
		panic(ErrIsNil.WithStackFrame())
	}
	v := new(numct.Nat)
	u.m.ModExp(v, u.v, exponent.v)
	return &Uint{v: v, m: u.m}
}

// ExpBounded performs exponentiation of the Uint element by a Nat exponent, using only the lower 'bits' bits of the exponent.
func (u *Uint) ExpBounded(exponent *Nat, bits uint) *Uint {
	if exponent == nil {
		panic(ErrIsNil.WithStackFrame())
	}
	boundedExp := exponent.v.Clone()
	boundedExp.Resize(int(bits))
	result := new(numct.Nat)
	u.m.ModExp(result, u.v, boundedExp)
	return &Uint{v: result, m: u.m}
}

// ExpI performs exponentiation of the Uint element by an Int exponent.
func (u *Uint) ExpI(exponent *Int) *Uint {
	if exponent == nil {
		panic(ErrIsNil.WithStackFrame())
	}
	v := new(numct.Nat)
	u.m.ModExpI(v, u.v, exponent.v)
	return &Uint{v: v, m: u.m}
}

// ExpIBounded performs exponentiation of the Uint element by an Int exponent, using only the lower 'bits' bits of the exponent.
func (u *Uint) ExpIBounded(exponent *Int, bits uint) *Uint {
	if exponent == nil {
		panic(ErrIsNil.WithStackFrame())
	}
	boundedExp := exponent.v.Clone()
	boundedExp.Resize(int(bits))
	result := new(numct.Nat)
	u.m.ModExpI(result, u.v, boundedExp)
	return &Uint{v: result, m: u.m}
}

// IsUnit checks if the Uint element is a unit (i.e., has a multiplicative inverse).
func (u *Uint) IsUnit() bool {
	return u.m.IsUnit(u.v) == ct.True
}

// Coprime checks if the Uint element is coprime to another Uint element.
func (u *Uint) Coprime(other *Uint) bool {
	errs.Must1(u.isValid(other))
	return u.v.Coprime(other.v) == ct.True
}

// IsProbablyPrime checks if the Uint element is probably prime.
func (u *Uint) IsProbablyPrime() bool {
	return u.v.IsProbablyPrime() == ct.True
}

// EuclideanDiv performs Euclidean division of the Uint element by another Uint element.
func (u *Uint) EuclideanDiv(other *Uint) (quot, rem *Uint, err error) {
	errs.Must1(u.isValid(other))
	if !u.Group().IsDomain() {
		return nil, nil, errs.New("not a euclidean domain")
	}

	var q, r numct.Nat
	if ok := q.EuclideanDiv(&r, u.v, other.v); ok == ct.False {
		return nil, nil, errs.New("division failed")
	}
	u.m.Mod(&q, &q)
	u.m.Mod(&r, &r)
	return &Uint{v: &q, m: u.m}, &Uint{v: &r, m: u.m}, nil
}

// EuclideanValuation returns the Euclidean valuation of the Uint element.
func (u *Uint) EuclideanValuation() algebra.Cardinal {
	if !u.Group().IsDomain() {
		panic(errs.New("not a euclidean domain"))
	}
	return cardinal.NewFromNumeric(u.v)
}

// TryNeg returns the additive inverse of the Uint element.
func (u *Uint) TryNeg() (*Uint, error) {
	return u.Neg(), nil
}

// TryInv returns the multiplicative inverse of the Uint element.
func (u *Uint) TryInv() (*Uint, error) {
	if !u.IsUnit() {
		return nil, errs.New("not a unit")
	}
	v := new(numct.Nat)
	u.m.ModInv(v, u.v)
	return &Uint{v: v, m: u.m}, nil
}

// TryDiv performs division of the Uint element by another Uint element.
func (u *Uint) TryDiv(other *Uint) (*Uint, error) {
	errs.Must1(u.isValid(other))
	v := new(numct.Nat)
	if ok := u.m.ModDiv(v, u.v, other.v); ok == ct.False {
		return nil, errs.New("division failed")
	}
	return &Uint{v: v, m: u.m}, nil
}

// Double returns the result of adding the Uint element to itself.
func (u *Uint) Double() *Uint {
	return u.Add(u)
}

// Square returns the result of multiplying the Uint element by itself.
func (u *Uint) Square() *Uint {
	return u.Mul(u)
}

// IsOpIdentity checks if the Uint element is the additive identity.
func (u *Uint) IsOpIdentity() bool {
	return u.IsZero()
}

// IsZero checks if the Uint element is zero.
func (u *Uint) IsZero() bool {
	return u.v.IsZero() == ct.True
}

// IsOne checks if the Uint element is one.
func (u *Uint) IsOne() bool {
	return u.v.IsOne() == ct.True
}

// IsBottom checks if the Uint element is the bottom element.
func (u *Uint) IsBottom() bool {
	return u.IsOne()
}

// IsTop checks if the Uint element is the top element.
func (u *Uint) IsTop() bool {
	v := u.m.Nat()
	v.Decrement()
	return u.v.Equal(v) == ct.True
}

// PartialCompare performs a partial comparison between two Uint elements.
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

// Compare performs a total comparison between two Uint elements.
func (u *Uint) Compare(other *Uint) base.Ordering {
	errs.Must1(u.isValid(other))
	lt, eq, gt := u.v.Compare(other.v)
	return base.Ordering(-1*int(lt) + 0*int(eq) + 1*int(gt))
}

// IsLessThanOrEqual checks if the Uint element is less than or equal to another Uint element.
func (u *Uint) IsLessThanOrEqual(other *Uint) bool {
	errs.Must1(u.isValid(other))
	lt, eq, _ := u.v.Compare(other.v)
	return lt|eq == ct.True
}

// EqualModulus checks if two Uint elements have the same modulus.
func (u *Uint) EqualModulus(other *Uint) bool {
	_, err := u.isValid(other)
	return err == nil
}

// Equal checks if two Uint elements are equal.
func (u *Uint) Equal(other *Uint) bool {
	_, err := u.isValid(other)
	return err == nil && u.v.Equal(other.v) == ct.True
}

// IsQuadraticResidue checks if the Uint element is a quadratic residue modulo the modulus.
func (u *Uint) IsQuadraticResidue() bool {
	_, err := u.Sqrt()
	return err == nil
}

// Sqrt computes the square root of the Uint element if it exists.
func (u *Uint) Sqrt() (*Uint, error) {
	v := new(numct.Nat)
	if ok := u.m.ModSqrt(v, u.v); ok == ct.False {
		return nil, errs.New("square root failed")
	}
	return &Uint{v: v, m: u.m}, nil
}

// Neg returns the additive inverse of the Uint element.
func (u *Uint) Neg() *Uint {
	v := new(numct.Nat)
	u.m.ModNeg(v, u.v)
	return &Uint{v: v, m: u.m}
}

// ScalarOp performs scalar multiplication of the Uint element by a Nat scalar.
func (u *Uint) ScalarOp(other *Nat) *Uint {
	return u.ScalarExp(other)
}

// IsTorsionFree checks if the Uint element is torsion-free.
func (*Uint) IsTorsionFree() bool {
	return true
}

// ScalarMul performs scalar multiplication of the Uint element by a Nat scalar.
func (u *Uint) ScalarMul(other *Nat) *Uint {
	out, err := u.Group().FromNat(u.Nat().Mul(other))
	if err != nil {
		panic(err)
	}
	return out
}

// ScalarExp performs exponentiation of the Uint element by a Nat scalar.
func (u *Uint) ScalarExp(other *Nat) *Uint {
	return u.Exp(other)
}

// Cardinal returns the cardinality of the Uint element.
func (u *Uint) Cardinal() cardinal.Cardinal {
	return cardinal.NewFromNumeric(u.v)
}

// Clone creates a copy of the Uint element.
func (u *Uint) Clone() *Uint {
	return &Uint{u.v.Clone(), u.m}
}

// Lift lifts the Uint element to an Int element.
func (u *Uint) Lift() *Int {
	out, err := Z().FromUint(u)
	if err != nil {
		panic(err)
	}
	return out
}

// HashCode returns a hash code for the Uint element.
func (u *Uint) HashCode() base.HashCode {
	return base.HashCode(u.v.Uint64() % u.m.Nat().Uint64())
}

// Modulus returns the modulus NatPlus of the Uint element.
func (u *Uint) Modulus() *NatPlus {
	out := &NatPlus{v: u.m.Nat(), m: u.m}
	return out
}

// ModulusCT returns the modulus Modulus of the Uint element.
func (u *Uint) ModulusCT() *numct.Modulus {
	return u.m
}

// String returns the string representation of the Uint element.
func (u *Uint) String() string {
	return u.v.String()
}

// Increment increments the Uint element by one.
func (u *Uint) Increment() *Uint {
	return u.Add(u.Group().One())
}

// Decrement decrements the Uint element by one.
func (u *Uint) Decrement() *Uint {
	return u.Sub(u.Group().One())
}

// Bytes returns the byte slice representation of the Uint element.
func (u *Uint) Bytes() []byte {
	return u.v.Bytes()
}

// BytesBE returns the big-endian byte slice representation of the Uint element.
func (u *Uint) BytesBE() []byte {
	return u.Bytes()
}

// Bit returns the i-th bit of the Uint element.
func (u *Uint) Bit(i uint) byte {
	return u.v.Bit(i)
}

// IsEven checks if the Uint element is even.
func (u *Uint) IsEven() bool {
	return u.v.IsEven() == ct.True
}

// IsOdd checks if the Uint element is odd.
func (u *Uint) IsOdd() bool {
	return u.v.IsOdd() == ct.True
}

// Abs returns the absolute value of the Uint element as a Nat.
func (u *Uint) Abs() *Nat {
	return &Nat{v: u.v.Clone()}
}

// Nat returns the Nat representation of the Uint element.
func (u *Uint) Nat() *Nat {
	return &Nat{v: u.v.Clone()}
}

// Big returns the big.Int representation of the Uint element.
func (u *Uint) Big() *big.Int {
	return u.v.Big()
}

// TrueLen returns the true length in bytes of the Uint element.
func (u *Uint) TrueLen() int {
	return u.v.TrueLen()
}

// AnnouncedLen returns the announced length in bytes of the Uint element.
func (u *Uint) AnnouncedLen() int {
	return u.v.AnnouncedLen()
}

// Select sets the Uint element to x0 if choice is true, and to x1 if choice is false.
func (u *Uint) Select(choice ct.Choice, x0, x1 *Uint) {
	u.v.Select(choice&x0.m.Nat().Equal(x1.m.Nat()), x0.v, x1.v)
	u.m = x0.m
}

// CondAssign conditionally assigns the value of x to the Uint element if choice is true.
func (u *Uint) CondAssign(choice ct.Choice, x *Uint) {
	u.v.CondAssign(choice, x.v)
	u.m = x.m
}
