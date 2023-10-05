package edwards25519

import (
	"bytes"
	"crypto/sha512"
	"crypto/subtle"
	"io"

	filippo "filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	ed "github.com/bwesterb/go-ristretto/edwards25519"
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/serialisation"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var _ curves.Point = (*Point)(nil)

type Point struct {
	Value *filippo.Point

	_ types.Incomparable
}

func (*Point) Curve() curves.Curve {
	return &edwards25519Instance
}

func (*Point) CurveName() string {
	return Name
}

func (p *Point) Random(reader io.Reader) curves.Point {
	var seed [64]byte
	_, _ = reader.Read(seed[:])
	return p.Hash(seed[:])
}

func (*Point) Hash(inputs ...[]byte) curves.Point {
	/// Perform hashing to the group using the Elligator2 map
	///
	/// See https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-11#section-6.7.1
	h := sha512.Sum512(bytes.Join(inputs, nil))
	var res [32]byte
	copy(res[:], h[:32])
	signBit := (res[31] & 0x80) >> 7

	fe := new(ed.FieldElement).SetBytes(&res).BytesInto(&res)
	m1 := elligatorEncode(fe)

	return toEdwards(m1, signBit)
}

func (*Point) Identity() curves.Point {
	return &Point{
		Value: filippo.NewIdentityPoint(),
	}
}

func (*Point) Generator() curves.Point {
	return &Point{
		Value: filippo.NewGeneratorPoint(),
	}
}

func (p *Point) Clone() curves.Point {
	return &Point{
		Value: filippo.NewIdentityPoint().Set(p.Value),
	}
}

func (p *Point) ClearCofactor() curves.Point {
	return &Point{
		Value: filippo.NewIdentityPoint().MultByCofactor(p.Value),
	}
}

func (p *Point) IsIdentity() bool {
	return p.Equal(p.Identity())
}

func (*Point) IsNegative() bool {
	// Negative points don't really exist in ed25519
	return false
}

func (p *Point) IsOnCurve() bool {
	_, err := filippo.NewIdentityPoint().SetBytes(p.ToAffineCompressed())
	return err == nil
}

func (p *Point) Double() curves.Point {
	return &Point{Value: filippo.NewIdentityPoint().Add(p.Value, p.Value)}
}

func (*Point) Scalar() curves.Scalar {
	return new(Scalar).Zero()
}

func (p *Point) Neg() curves.Point {
	return &Point{Value: filippo.NewIdentityPoint().Negate(p.Value)}
}

func (p *Point) Add(rhs curves.Point) curves.Point {
	if rhs == nil {
		panic("rhs in nil")
	}
	r, ok := rhs.(*Point)
	if ok {
		return &Point{Value: filippo.NewIdentityPoint().Add(p.Value, r.Value)}
	} else {
		panic("rhs in not PointEd25519")
	}
}

func (p *Point) Sub(rhs curves.Point) curves.Point {
	if rhs == nil {
		panic("rhs in nil")
	}
	r, ok := rhs.(*Point)
	if ok {
		rTmp := filippo.NewIdentityPoint().Negate(r.Value)
		return &Point{Value: filippo.NewIdentityPoint().Add(p.Value, rTmp)}
	} else {
		panic("rhs in not PointEd25519")
	}
}

func (p *Point) Mul(rhs curves.Scalar) curves.Point {
	if rhs == nil {
		panic("rhs in nil")
	}
	r, ok := rhs.(*Scalar)
	if ok {
		value := filippo.NewIdentityPoint().ScalarMult(r.Value, p.Value)
		return &Point{Value: value}
	} else {
		panic("rhs in not ScalarEd25519")
	}
}

// MangleScalarBitsAndMulByBasepointToProducePublicKey
// is a function for mangling the bits of a (formerly
// mathematically well-defined) "scalar" and multiplying it to produce a
// public key.
func (*Point) MangleScalarBitsAndMulByBasepointToProducePublicKey(rhs *Scalar) (*Point, error) {
	data := rhs.Value.Bytes()
	s, err := filippo.NewScalar().SetBytesWithClamping(data[:])
	if err != nil {
		return nil, errs.WrapFailed(err, "set bytes with clamping failed")
	}
	value := filippo.NewIdentityPoint().ScalarBaseMult(s)
	return &Point{Value: value}, nil
}

func (p *Point) Equal(rhs curves.Point) bool {
	r, ok := rhs.(*Point)
	if ok {
		// We would like to check that the point (X/Z, Y/Z) is equal to
		// the point (X'/Z', Y'/Z') without converting into affine
		// coordinates (x, y) and (x', y'), which requires two inversions.
		// We have that X = xZ and X' = x'Z'. Thus, x = x' is equivalent to
		// (xZ)Z' = (x'Z')Z, and similarly for the y-coordinate.
		return p.Value.Equal(r.Value) == 1
		//lhs1 := new(ed.FieldElement).Mul(&p.value.X, &r.value.Z)
		//rhs1 := new(ed.FieldElement).Mul(&r.value.X, &p.value.Z)
		//lhs2 := new(ed.FieldElement).Mul(&p.value.Y, &r.value.Z)
		//rhs2 := new(ed.FieldElement).Mul(&r.value.Y, &p.value.Z)
		//
		//return lhs1.Equals(rhs1) && lhs2.Equals(rhs2)
	} else {
		return false
	}
}

func (p *Point) Set(x, y *saferith.Nat) (curves.Point, error) {
	// check is identity
	xx := subtle.ConstantTimeCompare(x.Bytes(), []byte{})
	yy := subtle.ConstantTimeCompare(y.Bytes(), []byte{})
	if (xx | yy) != 0 {
		return p.Identity(), nil
	}
	xElem := new(ed.FieldElement).SetBigInt(x.Big())
	yElem := new(ed.FieldElement).SetBigInt(y.Big())

	var data [32]byte
	var affine [64]byte
	xElem.BytesInto(&data)
	copy(affine[:32], data[:])
	yElem.BytesInto(&data)
	copy(affine[32:], data[:])
	return p.FromAffineUncompressed(affine[:])
}

// sqrtRatio sets r to the non-negative square root of the ratio of u and v.
//
// If u/v is square, sqrtRatio returns r and 1. If u/v is not square, SqrtRatio
// sets r according to Section 4.3 of draft-irtf-cfrg-ristretto255-decaf448-00,
// and returns r and 0.
func sqrtRatio(u, v *ed.FieldElement) (r *ed.FieldElement, wasSquare bool) {
	sqrtM1 := ed.FieldElement{
		533094393274173, 2016890930128738, 18285341111199,
		134597186663265, 1486323764102114,
	}
	a := new(ed.FieldElement)
	b := new(ed.FieldElement)
	r = new(ed.FieldElement)

	// r = (u * v3) * (u * v7)^((p-5)/8)
	v2 := a.Square(v)
	uv3 := b.Mul(u, b.Mul(v2, v))
	uv7 := a.Mul(uv3, a.Square(v2))
	r.Mul(uv3, r.Exp22523(uv7))

	check := a.Mul(v, a.Square(r)) // check = v * r^2

	uNeg := b.Neg(u)
	correctSignSqrt := check.Equals(u)
	flippedSignSqrt := check.Equals(uNeg)
	flippedSignSqrtI := check.Equals(uNeg.Mul(uNeg, &sqrtM1))

	rPrime := b.Mul(r, &sqrtM1) // r_prime = SQRT_M1 * r
	// r = CT_SELECT(r_prime IF flipped_sign_sqrt | flipped_sign_sqrt_i ELSE r)
	cselect(r, rPrime, r, flippedSignSqrt || flippedSignSqrtI)

	r.Abs(r) // Choose the nonnegative square root.
	return r, correctSignSqrt || flippedSignSqrt
}

// cselect sets v to a if cond == 1, and to b if cond == 0.
func cselect(v, a, b *ed.FieldElement, cond bool) {
	const mask64Bits uint64 = (1 << 64) - 1

	m := uint64(0)
	if cond {
		m = mask64Bits
	}

	v[0] = (m & a[0]) | (^m & b[0])
	v[1] = (m & a[1]) | (^m & b[1])
	v[2] = (m & a[2]) | (^m & b[2])
	v[3] = (m & a[3]) | (^m & b[3])
	v[4] = (m & a[4]) | (^m & b[4])
}

func (p *Point) ToAffineCompressed() []byte {
	return p.Value.Bytes()
}

func (p *Point) ToAffineUncompressed() []byte {
	x, y, z, _ := p.Value.ExtendedCoordinates()
	recip := new(field.Element).Invert(z)
	x.Multiply(x, recip)
	y.Multiply(y, recip)
	var out [64]byte
	copy(out[:32], x.Bytes())
	copy(out[32:], y.Bytes())
	return out[:]
}

func (*Point) FromAffineCompressed(inBytes []byte) (curves.Point, error) {
	pt, err := filippo.NewIdentityPoint().SetBytes(inBytes)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "set bytes method failed")
	}
	return &Point{Value: pt}, nil
}

func (*Point) FromAffineUncompressed(inBytes []byte) (curves.Point, error) {
	if len(inBytes) != 64 {
		return nil, errs.NewInvalidLength("invalid byte sequence")
	}
	if bytes.Equal(inBytes, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
		return &Point{Value: filippo.NewIdentityPoint()}, nil
	}
	x, err := new(field.Element).SetBytes(inBytes[:32])
	if err != nil {
		return nil, errs.WrapInvalidCoordinates(err, "x")
	}
	y, err := new(field.Element).SetBytes(inBytes[32:])
	if err != nil {
		return nil, errs.WrapInvalidCoordinates(err, "y")
	}
	z := new(field.Element).One()
	t := new(field.Element).Multiply(x, y)
	value, err := filippo.NewIdentityPoint().SetExtendedCoordinates(x, y, z, t)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "set extended coordinates")
	}
	return &Point{Value: value}, nil
}

func (p *Point) MarshalBinary() ([]byte, error) {
	point, err := serialisation.PointMarshalBinary(p)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "marshal to point failed")
	}
	return point, nil
}

func (p *Point) UnmarshalBinary(input []byte) error {
	pt, err := serialisation.PointUnmarshalBinary(&edwards25519Instance, input)
	if err != nil {
		return errs.WrapSerializationError(err, "unmarshal binary failed")
	}
	ppt, ok := pt.(*Point)
	if !ok {
		return errs.NewInvalidType("invalid point")
	}
	p.Value = ppt.Value
	return nil
}

func (p *Point) MarshalText() ([]byte, error) {
	t, err := serialisation.PointMarshalText(p)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "marshal to text failed")
	}
	return t, nil
}

func (p *Point) UnmarshalText(input []byte) error {
	pt, err := serialisation.PointUnmarshalText(&edwards25519Instance, input)
	if err != nil {
		return errs.WrapSerializationError(err, "unmarshal binary failed")
	}
	ppt, ok := pt.(*Point)
	if !ok {
		return errs.NewInvalidType("invalid point")
	}
	p.Value = ppt.Value
	return nil
}

func (p *Point) MarshalJSON() ([]byte, error) {
	point, err := serialisation.PointMarshalJson(p)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "marshal to json failed")
	}
	return point, nil
}

func (p *Point) UnmarshalJSON(input []byte) error {
	pt, err := serialisation.NewPointFromJSON(&edwards25519Instance, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not extract a point from json")
	}
	P, ok := pt.(*Point)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	p.Value = P.Value
	return nil
}

func (p *Point) GetEdwardsPoint() *filippo.Point {
	return filippo.NewIdentityPoint().Set(p.Value)
}

func (*Point) SetEdwardsPoint(pt *filippo.Point) *Point {
	return &Point{Value: filippo.NewIdentityPoint().Set(pt)}
}

func (p *Point) IsSmallOrder() bool {
	// pBytes := p.ToAffineCompressed()
	// pHex := hex.EncodeToString(pBytes)

	// for _, smallOrderAffinecurves.Point := range []string{
	// 	"0100000000000000000000000000000000000000000000000000000000000000",
	// 	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	// 	"0000000000000000000000000000000000000000000000000000000000000080",
	// 	"0000000000000000000000000000000000000000000000000000000000000000",
	// 	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	// 	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	// 	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	// 	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	// } {
	// 	if pHex == smallOrderAffinecurves.Point {
	// 		return true
	// 	}
	// }
	// return false

	// performance difference is negligible
	return p.ClearCofactor().IsIdentity()
}

func (p *Point) X() curves.FieldElement {
	x, _, z, _ := p.Value.ExtendedCoordinates()
	recip := new(field.Element).Invert(z)
	xx := new(field.Element).Multiply(x, recip)
	return &FieldElement{
		v: xx,
	}
}

func (p *Point) Y() curves.FieldElement {
	_, y, z, _ := p.Value.ExtendedCoordinates()
	recip := new(field.Element).Invert(z)
	y.Multiply(y, recip)
	return &FieldElement{
		v: y,
	}
}

func (p *Point) ExtendedX() curves.FieldElement {
	x, _, _, _ := p.Value.ExtendedCoordinates()
	return &FieldElement{
		v: x,
	}
}

func (p *Point) ExtendedY() curves.FieldElement {
	_, y, _, _ := p.Value.ExtendedCoordinates()
	return &FieldElement{
		v: y,
	}
}

func (p *Point) ExtendedZ() curves.FieldElement {
	_, _, z, _ := p.Value.ExtendedCoordinates()
	return &FieldElement{
		v: z,
	}
}

func (p *Point) ExtendedT() curves.FieldElement {
	_, _, _, t := p.Value.ExtendedCoordinates()
	return &FieldElement{
		v: t,
	}
}

// Attempt to convert to an `EdwardsPoint`, using the supplied
// choice of sign for the `EdwardsPoint`.
//   - `sign`: a `u8` donating the desired sign of the resulting
//     `EdwardsPoint`.  `0` denotes positive and `1` negative.
func toEdwards(u *ed.FieldElement, sign byte) *Point {
	one := new(ed.FieldElement).SetOne()
	// To decompress the Montgomery u coordinate to an
	// `EdwardsPoint`, we apply the birational map to obtain the
	// Edwards y coordinate, then do Edwards decompression.
	//
	// The birational map is y = (u-1)/(u+1).
	//
	// The exceptional points are the zeros of the denominator,
	// i.e., u = -1.
	//
	// But when u = -1, v^2 = u*(u^2+486662*u+1) = 486660.
	//
	// Since this is nonsquare mod p, u = -1 corresponds to a point
	// on the twist, not the curve, so we can reject it early.
	if u.Equals(new(ed.FieldElement).Neg(one)) {
		return nil
	}

	// y = (u-1)/(u+1)
	yLhs := new(ed.FieldElement).Sub(u, one)
	yRhs := new(ed.FieldElement).Add(u, one)
	yInv := new(ed.FieldElement).Inverse(yRhs)
	y := new(ed.FieldElement).Mul(yLhs, yInv)
	yBytes := y.Bytes()
	yBytes[31] ^= sign << 7

	pt, err := filippo.NewIdentityPoint().SetBytes(yBytes[:])
	if err != nil {
		return nil
	}
	pt.MultByCofactor(pt)
	return &Point{Value: pt}
}

// Perform the Elligator2 mapping to a Montgomery point encoded as a 32 byte value
//
// See <https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-11#section-6.7.1>
func elligatorEncode(r0 *ed.FieldElement) *ed.FieldElement {
	montgomeryA := &ed.FieldElement{
		486662, 0, 0, 0, 0,
	}
	// montgomeryANeg is equal to -486662.
	montgomeryANeg := &ed.FieldElement{
		2251799813198567,
		2251799813685247,
		2251799813685247,
		2251799813685247,
		2251799813685247,
	}
	t := new(ed.FieldElement)
	one := new(ed.FieldElement).SetOne()
	// 2r^2
	d1 := new(ed.FieldElement).Add(one, t.DoubledSquare(r0))
	// A/(1+2r^2)
	d := new(ed.FieldElement).Mul(montgomeryANeg, t.Inverse(d1))
	dsq := new(ed.FieldElement).Square(d)
	au := new(ed.FieldElement).Mul(montgomeryA, d)

	inner := new(ed.FieldElement).Add(dsq, au)
	inner.Add(inner, one)

	// d^3 + Ad^2 + d
	eps := new(ed.FieldElement).Mul(d, inner)
	_, wasSquare := sqrtRatio(eps, one)

	zero := new(ed.FieldElement).SetZero()
	aTemp := new(ed.FieldElement).SetZero()
	// 0 or A if non-square
	cselect(aTemp, zero, montgomeryA, wasSquare)
	// d, or d+A if non-square
	u := new(ed.FieldElement).Add(d, aTemp)
	// d or -d-A if non-square
	cselect(u, u, new(ed.FieldElement).Neg(u), wasSquare)
	return u
}
