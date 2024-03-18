package pallas

import (
	"crypto/subtle"
	"io"
	"reflect"
	"strings"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/hash2curve"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas/impl/fp"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas/impl/fq"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

const Name = "pallas"

var (
	pallasInitonce sync.Once
	pallasInstance Curve

	b        = new(fp.Fp).SetUint64(5)
	three    = &fp.Fp{0x6b0ee5d0fffffff5, 0x86f76d2b99b14bd0, 0xfffffffffffffffe, 0x3fffffffffffffff}
	eight    = &fp.Fp{0x7387134cffffffe1, 0xd973797adfadd5a8, 0xfffffffffffffffb, 0x3fffffffffffffff}
	bool2int = map[bool]int{
		true:  1,
		false: 0,
	}
)

var isomapper = [13]*fp.Fp{
	new(fp.Fp).SetRaw(&[4]uint64{0x775f6034aaaaaaab, 0x4081775473d8375b, 0xe38e38e38e38e38e, 0x0e38e38e38e38e38}),
	new(fp.Fp).SetRaw(&[4]uint64{0x8cf863b02814fb76, 0x0f93b82ee4b99495, 0x267c7ffa51cf412a, 0x3509afd51872d88e}),
	new(fp.Fp).SetRaw(&[4]uint64{0x0eb64faef37ea4f7, 0x380af066cfeb6d69, 0x98c7d7ac3d98fd13, 0x17329b9ec5253753}),
	new(fp.Fp).SetRaw(&[4]uint64{0xeebec06955555580, 0x8102eea8e7b06eb6, 0xc71c71c71c71c71c, 0x1c71c71c71c71c71}),
	new(fp.Fp).SetRaw(&[4]uint64{0xc47f2ab668bcd71f, 0x9c434ac1c96b6980, 0x5a607fcce0494a79, 0x1d572e7ddc099cff}),
	new(fp.Fp).SetRaw(&[4]uint64{0x2aa3af1eae5b6604, 0xb4abf9fb9a1fc81c, 0x1d13bf2a7f22b105, 0x325669becaecd5d1}),
	new(fp.Fp).SetRaw(&[4]uint64{0x5ad985b5e38e38e4, 0x7642b01ad461bad2, 0x4bda12f684bda12f, 0x1a12f684bda12f68}),
	new(fp.Fp).SetRaw(&[4]uint64{0xc67c31d8140a7dbb, 0x07c9dc17725cca4a, 0x133e3ffd28e7a095, 0x1a84d7ea8c396c47}),
	new(fp.Fp).SetRaw(&[4]uint64{0x02e2be87d225b234, 0x1765e924f7459378, 0x303216cce1db9ff1, 0x3fb98ff0d2ddcadd}),
	new(fp.Fp).SetRaw(&[4]uint64{0x93e53ab371c71c4f, 0x0ac03e8e134eb3e4, 0x7b425ed097b425ed, 0x025ed097b425ed09}),
	new(fp.Fp).SetRaw(&[4]uint64{0x5a28279b1d1b42ae, 0x5941a3a4a97aa1b3, 0x0790bfb3506defb6, 0x0c02c5bcca0e6b7f}),
	new(fp.Fp).SetRaw(&[4]uint64{0x4d90ab820b12320a, 0xd976bbfabbc5661d, 0x573b3d7f7d681310, 0x17033d3c60c68173}),
	new(fp.Fp).SetRaw(&[4]uint64{0x992d30ecfffffde5, 0x224698fc094cf91b, 0x0000000000000000, 0x4000000000000000}),
}

var (
	isoa = new(fp.Fp).SetRaw(&[4]uint64{0x92bb4b0b657a014b, 0xb74134581a27a59f, 0x49be2d7258370742, 0x18354a2eb0ea8c9c})
	isob = new(fp.Fp).SetRaw(&[4]uint64{1265, 0, 0, 0})
	z    = new(fp.Fp).SetRaw(&[4]uint64{0x992d30ecfffffff4, 0x224698fc094cf91b, 0x0000000000000000, 0x4000000000000000})
)

var _ curves.Curve = (*Curve)(nil)

type Curve struct {
	hash2curve.CurveHasher

	_ ds.Incomparable
}

func pallasInit() {
	pallasInstance = Curve{}
	pallasInstance.CurveHasher = hash2curve.NewCurveHasherSha256(
		curves.Curve(&pallasInstance),
		base.HASH2CURVE_APP_TAG,
		hash2curve.DstTagSswu,
	)
}

// SetHasherAppTag sets the hasher to use for hash-to-curve operations with a
// custom "appTag". Not exposed in the `curves.Curve` interface, as by
// default we should use the library-wide HASH2CURVE_APP_TAG for compatibility.
func (c *Curve) SetHasherAppTag(appTag string) {
	c.CurveHasher = hash2curve.NewCurveHasherSha256(
		curves.Curve(&pallasInstance),
		appTag,
		hash2curve.DstTagSswu,
	)
}

func NewCurve() *Curve {
	pallasInitonce.Do(pallasInit)
	return &pallasInstance
}

// === Basic Methods.

func (*Curve) Name() string {
	return Name
}

func (c *Curve) Order() *saferith.Modulus {
	return c.SubGroupOrder()
}

func (c *Curve) Element() curves.Point {
	return c.Identity()
}

func (c *Curve) OperateOver(operator algebra.Operator, ps ...curves.Point) (curves.Point, error) {
	if operator != algebra.PointAddition {
		return nil, errs.NewType("operator %v is not supported", operator)
	}
	current := c.Identity()
	for _, p := range ps {
		current = current.Operate(p)
	}
	return current, nil
}

func (*Curve) Operators() []algebra.Operator {
	return []algebra.Operator{algebra.PointAddition}
}

func (c *Curve) Random(prng io.Reader) (curves.Point, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	var seed [64]byte
	if _, err := io.ReadFull(prng, seed[:]); err != nil {
		return nil, errs.NewRandomSample("cannot read prng")
	}
	return c.Hash(seed[:])
}

func (c *Curve) Hash(input []byte) (curves.Point, error) {
	return c.HashWithDst(input, nil)
}

func (*Curve) HashWithDst(input, dst []byte) (curves.Point, error) {
	p := new(Ep)
	u, err := NewCurve().HashToFieldElements(2, input, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "hash to field element of P256 failed")
	}
	u0, ok0 := u[0].(*BaseFieldElement)
	u1, ok1 := u[1].(*BaseFieldElement)
	if !ok0 || !ok1 {
		return nil, errs.NewType("cast to P256 field element failed")
	}
	p = p.Map(u0.V, u1.V)
	return &Point{V: p}, nil
}

func (c *Curve) Select(choice int, x0, x1 curves.Point) curves.Point {
	x0p, ok0 := x0.(*Point)
	x1p, ok1 := x1.(*Point)
	p, okp := c.Element().(*Point)
	if !ok0 || !ok1 || okp {
		panic("Not a K256 point")
	}
	p.V.X.CMove(x0p.V.X, x1p.V.X, choice)
	p.V.Y.CMove(x0p.V.Y, x1p.V.Y, choice)
	p.V.Z.CMove(x0p.V.Z, x1p.V.Z, choice)
	return p
}

// === Additive Groupoid Methods.

func (*Curve) Add(x curves.Point, ys ...curves.Point) curves.Point {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum
}

// === Monoid Methods.

func (*Curve) Identity() curves.Point {
	return &Point{V: new(Ep).Identity()}
}

// === Additive Monoid Methods.

func (c *Curve) AdditiveIdentity() curves.Point {
	return c.Identity()
}

// === Group Methods.

func (*Curve) Cofactor() *saferith.Nat {
	return new(saferith.Nat).SetUint64(1)
}

// === Additive Group Methods.

func (*Curve) Sub(x curves.Point, ys ...curves.Point) curves.Point {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum
}

// === Cyclic Group Methods.

func (*Curve) Generator() curves.Point {
	return &Point{V: new(Ep).Generator()}
}

// === Variety Methods.

func (*Curve) Dimension() int {
	return 1
}

func (*Curve) Discriminant() *saferith.Int {
	result, _ := new(saferith.Nat).SetHex(strings.ToUpper("2a30"))
	return new(saferith.Int).SetNat(result).Neg(1)
}

// === Algebraic Curve Methods.

func (*Curve) BaseField() curves.BaseField {
	return NewBaseField()
}

func (c *Curve) NewPoint(x, y curves.BaseFieldElement) (curves.Point, error) {
	if x == nil || y == nil {
		return nil, errs.NewIsNil("argument is nil")
	}

	xx, ok := x.(*BaseFieldElement)
	if !ok {
		return nil, errs.NewType("x is not the right type")
	}
	yy, ok := y.(*BaseFieldElement)
	if !ok {
		return nil, errs.NewType("y is not the right type")
	}

	xxx := subtle.ConstantTimeCompare(xx.Bytes(), []byte{})
	yyy := subtle.ConstantTimeCompare(yy.Bytes(), []byte{})
	xElem := new(fp.Fp).SetNat(xx.Nat())
	var data [32]byte
	if yyy == 1 {
		if xxx == 1 {
			return &Point{V: new(Ep).Identity()}, nil
		}
		data = xElem.Bytes()
		return c.Point().FromAffineCompressed(data[:])
	}
	yElem := new(fp.Fp).SetNat(yy.Nat())
	value := &Ep{X: xElem, Y: yElem, Z: new(fp.Fp).SetOne()}
	if !value.IsOnCurve() {
		return nil, errs.NewMembership("point is not on the curve")
	}
	return &Point{V: value}, nil
}

// === Elliptic Curve Methods.

func (c *Curve) ScalarRing() curves.ScalarField {
	return c.ScalarField()
}

func (*Curve) ScalarField() curves.ScalarField {
	return NewScalarField()
}

func (c *Curve) Point() curves.Point {
	return c.Identity()
}

func (c *Curve) Scalar() curves.Scalar {
	return c.ScalarField().Element()
}

func (c *Curve) BaseFieldElement() curves.BaseFieldElement {
	return c.BaseField().Zero()
}

func (c *Curve) FrobeniusEndomorphism(p curves.Point) curves.Point {
	pp, ok := p.(*Point)
	if !ok {
		panic("given point is not of the right type")
	}
	x := pp.AffineX()
	y := pp.AffineY()
	characteristic := NewBaseFieldElement(0).SetNat(NewBaseField().Characteristic())
	result, err := c.NewPoint(x.Exp(characteristic), y.Exp(characteristic))
	if err != nil {
		panic(errs.WrapFailed(err, "forbenius endomorphism did not succeed"))
	}
	return result
}

func (*Curve) TraceOfFrobenius() *saferith.Int {
	// TODO: find number of rational points
	panic("not implemented.")
}

func (*Curve) JInvariant() *saferith.Int {
	return new(saferith.Int).SetUint64(0)
}

// === Prime SubGroup Methods.

func (*Curve) SubGroupOrder() *saferith.Modulus {
	return fq.Modulus
}

func (c *Curve) ScalarBaseMult(sc curves.Scalar) curves.Point {
	return c.Generator().Mul(sc)
}

func (*Curve) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	eps := make([]*Ep, len(points))
	for i, pt := range points {
		ps, ok := pt.(*Point)
		if !ok {
			return nil, errs.NewFailed("invalid point type %s, expected PointPallas", reflect.TypeOf(pt).Name())
		}
		eps[i] = ps.V
	}
	nScalars := make([]*saferith.Nat, len(scalars))
	for i, s := range scalars {
		sc, ok := s.(*Scalar)
		if !ok {
			return nil, errs.NewType("not a pallas scalar")
		}
		nScalars[i] = sc.V.Nat()
	}

	value := PippengerMultiScalarMultPallas(eps, nScalars)
	return &Point{V: value}, nil
}

func (*Curve) DeriveFromAffineX(x curves.BaseFieldElement) (evenY, oddY curves.Point, err error) {
	xc, ok := x.(*BaseFieldElement)
	if !ok {
		return nil, nil, errs.NewType("provided x coordinate is not a pallas field element")
	}
	rhs := rhsPallas(xc.V)
	y, wasQr := new(fp.Fp).Sqrt(rhs)
	if !wasQr {
		return nil, nil, errs.NewCoordinates("x was not a quadratic residue")
	}
	p1e := new(Ep)
	p1e.X = xc.V
	p1e.Y = new(fp.Fp).Set(y)
	p1e.Z = new(fp.Fp).SetOne()

	p2e := new(Ep)
	p2e.X = xc.V
	p2e.Y = new(fp.Fp).Neg(new(fp.Fp).Set(y))
	p2e.Z = new(fp.Fp).SetOne()

	p1 := &Point{V: p1e}
	p2 := &Point{V: p2e}

	if p1.AffineY().IsEven() {
		return p1, p2, nil
	}
	return p2, p1, nil
}

// === Misc.

// rhs of the curve equation.
func rhsPallas(x *fp.Fp) *fp.Fp {
	x2 := new(fp.Fp).Square(x)
	x3 := new(fp.Fp).Mul(x, x2)
	return new(fp.Fp).Add(x3, b)
}

func PippengerMultiScalarMultPallas(points []*Ep, scalars []*saferith.Nat) *Ep {
	if len(points) != len(scalars) {
		return nil
	}

	const w = 6

	bucketSize := uint64((1 << w) - 1)
	windows := make([]*Ep, 255/w+1)
	for i := range windows {
		windows[i] = new(Ep).Identity()
	}
	bucket := make([]*Ep, bucketSize)

	for j := 0; j < len(windows); j++ {
		for i := uint64(0); i < bucketSize; i++ {
			bucket[i] = new(Ep).Identity()
		}

		for i := 0; i < len(scalars); i++ {
			index := bucketSize & new(saferith.Nat).Rsh(scalars[i], uint(w*j), fp.Modulus.BitLen()).Uint64()
			if index != 0 {
				bucket[index-1].Add(bucket[index-1], points[i])
			}
		}

		acc, sum := new(Ep).Identity(), new(Ep).Identity()

		for i := int64(bucketSize) - 1; i >= 0; i-- {
			sum.Add(sum, bucket[i])
			acc.Add(acc, sum)
		}
		windows[j] = acc
	}

	acc := new(Ep).Identity()
	for i := len(windows) - 1; i >= 0; i-- {
		for j := 0; j < w; j++ {
			acc.Double(acc)
		}
		acc.Add(acc, windows[i])
	}
	return acc
}

// Implements a degree 3 isogeny map.
// The input and output are in Jacobian coordinates, using the method
// in "Avoiding inversions" [WB2019, section 4.3].
func isoMap(p *Ep) *Ep {
	var z [4]*fp.Fp
	z[0] = new(fp.Fp).Square(p.Z)    // z^2
	z[1] = new(fp.Fp).Mul(z[0], p.Z) // z^3
	z[2] = new(fp.Fp).Square(z[0])   // z^4
	z[3] = new(fp.Fp).Square(z[1])   // z^6

	// ((iso[0] * x + iso[1] * z^2) * x + iso[2] * z^4) * x + iso[3] * z^6
	numX := new(fp.Fp).Set(isomapper[0])
	numX.Mul(numX, p.X)
	numX.Add(numX, new(fp.Fp).Mul(isomapper[1], z[0]))
	numX.Mul(numX, p.X)
	numX.Add(numX, new(fp.Fp).Mul(isomapper[2], z[2]))
	numX.Mul(numX, p.X)
	numX.Add(numX, new(fp.Fp).Mul(isomapper[3], z[3]))

	// (z^2 * x + iso[4] * z^4) * x + iso[5] * z^6
	divX := new(fp.Fp).Set(z[0])
	divX.Mul(divX, p.X)
	divX.Add(divX, new(fp.Fp).Mul(isomapper[4], z[2]))
	divX.Mul(divX, p.X)
	divX.Add(divX, new(fp.Fp).Mul(isomapper[5], z[3]))

	// (((iso[6] * x + iso[7] * z2) * x + iso[8] * z4) * x + iso[9] * z6) * y
	numY := new(fp.Fp).Set(isomapper[6])
	numY.Mul(numY, p.X)
	numY.Add(numY, new(fp.Fp).Mul(isomapper[7], z[0]))
	numY.Mul(numY, p.X)
	numY.Add(numY, new(fp.Fp).Mul(isomapper[8], z[2]))
	numY.Mul(numY, p.X)
	numY.Add(numY, new(fp.Fp).Mul(isomapper[9], z[3]))
	numY.Mul(numY, p.Y)

	// (((x + iso[10] * z2) * x + iso[11] * z4) * x + iso[12] * z6) * z3
	divY := new(fp.Fp).Set(p.X)
	divY.Add(divY, new(fp.Fp).Mul(isomapper[10], z[0]))
	divY.Mul(divY, p.X)
	divY.Add(divY, new(fp.Fp).Mul(isomapper[11], z[2]))
	divY.Mul(divY, p.X)
	divY.Add(divY, new(fp.Fp).Mul(isomapper[12], z[3]))
	divY.Mul(divY, z[1])

	z0 := new(fp.Fp).Mul(divX, divY)
	x := new(fp.Fp).Mul(numX, divY)
	x.Mul(x, z0)
	y := new(fp.Fp).Mul(numY, divX)
	y.Mul(y, new(fp.Fp).Square(z0))

	return &Ep{
		X: x, Y: y, Z: z0,
	}
}

func mapSswu(u *fp.Fp) *Ep {
	// c1 := new(fp.Fp).Neg(isoa)
	// c1.Invert(c1)
	// c1.Mul(isob, c1)
	c1 := &fp.Fp{
		0x1ee770ce078456ec,
		0x48cfd64c2ce76be0,
		0x43d5774c0ab79e2f,
		0x23368d2bdce28cf3,
	}
	// c2 := new(fp.Fp).Neg(z)
	// c2.Invert(c2)
	c2 := &fp.Fp{
		0x03df915f89d89d8a,
		0x8f1e8db09ef82653,
		0xd89d89d89d89d89d,
		0x1d89d89d89d89d89,
	}

	u2 := new(fp.Fp).Square(u)
	tv1 := new(fp.Fp).Mul(z, u2)
	tv2 := new(fp.Fp).Square(tv1)
	x1 := new(fp.Fp).Add(tv1, tv2)
	x1.Invert(x1)
	e1 := bool2int[x1.IsZero()]
	x1.Add(x1, new(fp.Fp).SetOne())
	x1.CMove(x1, c2, e1)
	x1.Mul(x1, c1)
	gx1 := new(fp.Fp).Square(x1)
	gx1.Add(gx1, isoa)
	gx1.Mul(gx1, x1)
	gx1.Add(gx1, isob)
	x2 := new(fp.Fp).Mul(tv1, x1)
	tv2.Mul(tv1, tv2)
	gx2 := new(fp.Fp).Mul(gx1, tv2)
	gx1Sqrt, e2 := new(fp.Fp).Sqrt(gx1)
	x := new(fp.Fp).CMove(x2, x1, bool2int[e2])
	gx2Sqrt, _ := new(fp.Fp).Sqrt(gx2)
	y := new(fp.Fp).CMove(gx2Sqrt, gx1Sqrt, bool2int[e2])
	e3 := u.IsOdd() == y.IsOdd()
	y.CMove(new(fp.Fp).Neg(y), y, bool2int[e3])

	return &Ep{
		X: x, Y: y, Z: new(fp.Fp).SetOne(),
	}
}
