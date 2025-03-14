package pasta

import (
	"io"
	"iter"
	"reflect"
	"strings"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/bitstring"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/h2c"
	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
	pastaImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/pasta/impl"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	saferithUtils "github.com/bronlabs/bron-crypto/pkg/base/utils/saferith"
)

const (
	PallasName                  = "pallas"
	PallasHash2CurveSuite       = "pallas_XMD:BLAKE2b_SSWU_RO_"
	PallasHash2CurveScalarSuite = "pallas_XMD:BLAKE2b_SSWU_RO_SC_"
)

var (
	pallasInitOnce sync.Once
	pallasInstance PallasCurve
	pallasOrder    *saferith.Modulus
)

var _ curves.Curve = (*PallasCurve)(nil)

type PallasCurve struct {
	_ ds.Incomparable
}

func pallasInit() {
	pallasOrder = saferith.ModulusFromBytes(bitstring.ReverseBytes(pastaImpl.FqModulus[:]))

	pallasInstance = PallasCurve{}
}

func NewPallasCurve() *PallasCurve {
	pallasInitOnce.Do(pallasInit)
	return &pallasInstance
}

func (*PallasCurve) HashToFieldElements(count int, dstPrefix string, msg []byte) (u []curves.BaseFieldElement, err error) {
	out := make([]pastaImpl.Fp, count)
	h2c.HashToField(out[:], pastaImpl.PallasCurveHasherParams{}, dstPrefix+PallasHash2CurveSuite, msg)

	u = make([]curves.BaseFieldElement, count)
	for i := range out {
		v := new(PallasBaseFieldElement)
		v.V.Set(&out[i])
		u[i] = v
	}

	return u, nil
}

func (*PallasCurve) HashToScalars(count int, dstPrefix string, msg []byte) (u []curves.Scalar, err error) {
	out := make([]pastaImpl.Fq, count)
	h2c.HashToField(out[:], pastaImpl.PallasCurveHasherParams{}, dstPrefix+PallasHash2CurveScalarSuite, msg)

	u = make([]curves.Scalar, count)
	for i := range out {
		v := new(PallasScalar)
		v.V.Set(&out[i])
		u[i] = v
	}

	return u, nil
}

func (*PallasCurve) Cardinality() *saferith.Nat {
	//TODO implement me
	panic("implement me")
}

func (*PallasCurve) Contains(e curves.Point) bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasCurve) Iter() iter.Seq[curves.Point] {
	//TODO implement me
	panic("implement me")
}

func (*PallasCurve) Operators() []algebra.BinaryOperator[curves.Point] {
	//TODO implement me
	panic("implement me")
}

func (c *PallasCurve) Unwrap() curves.Curve {
	return c
}

func (*PallasCurve) IsDefinedUnder(operator algebra.BinaryOperator[curves.Point]) bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasCurve) Op(operator algebra.BinaryOperator[curves.Point], x algebra.GroupoidElement[curves.Curve, curves.Point], ys ...algebra.GroupoidElement[curves.Curve, curves.Point]) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasCurve) Addition() algebra.Addition[curves.Point] {
	//TODO implement me
	panic("implement me")
}

func (*PallasCurve) ModuleScalarRing() algebra.ModuleBaseRing[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*PallasCurve) AlgebraicVarietyBaseField() algebra.AlgebraicVarietyBaseField[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*PallasCurve) VectorSpaceScalarField() algebra.VectorSpaceBaseField[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (c *PallasCurve) BasePoint() curves.Point {
	return c.Generator()
}

func (*PallasCurve) DLog(b, x algebra.CyclicGroupElement[curves.Curve, curves.Point], under algebra.BinaryOperator[curves.Point]) (*saferith.Nat, error) {
	//TODO implement me
	panic("implement me")
}

func (c *PallasCurve) SuperGroupOrder() *saferith.Modulus {
	return c.Order()
}

func (*PallasCurve) ElementSize() int {
	return pastaImpl.FpBytes
}

func (*PallasCurve) WideElementSize() int {
	return pastaImpl.FpWideBytes
}

func (*PallasCurve) Name() string {
	return PallasName
}

func (c *PallasCurve) Order() *saferith.Modulus {
	return c.SubGroupOrder()
}

func (c *PallasCurve) Element() curves.Point {
	return c.AdditiveIdentity()
}

func (*PallasCurve) Random(prng io.Reader) (curves.Point, error) {
	p := new(PallasPoint)
	ok := p.V.SetRandom(prng)
	if ok != 1 {
		return nil, errs.NewRandomSample("pallas point")
	}

	return p, nil
}

func (c *PallasCurve) Hash(input []byte) (curves.Point, error) {
	return c.HashWithDst(base.Hash2CurveAppTag+PallasHash2CurveSuite, input)
}

func (*PallasCurve) HashWithDst(dst string, input []byte) (curves.Point, error) {
	p := new(PallasPoint)
	p.V.Hash(dst, input)
	return p, nil
}

func (*PallasCurve) Select(choice uint64, x0, x1 curves.Point) curves.Point {
	x0p, ok0 := x0.(*PallasPoint)
	if !ok0 {
		panic("x0 is not a non-empty Pallas point")
	}
	x1p, ok1 := x1.(*PallasPoint)
	if !ok1 {
		panic("x1 is not a non-empty Pallas point")
	}

	p := new(PallasPoint)
	p.V.Select(choice, &x0p.V, &x1p.V)
	return p
}

// === Additive Groupoid Methods.

func (*PallasCurve) Add(x algebra.AdditiveGroupoidElement[curves.Curve, curves.Point], ys ...algebra.AdditiveGroupoidElement[curves.Curve, curves.Point]) curves.Point {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum.Unwrap()
}

// === Monoid Methods.

func (*PallasCurve) Identity(under algebra.BinaryOperator[curves.Point]) (curves.Point, error) {
	panic("implement me")
}

// === Additive Monoid Methods.

func (*PallasCurve) AdditiveIdentity() curves.Point {
	id := new(PallasPoint)
	id.V.SetIdentity()
	return id
}

// === Group Methods.

func (*PallasCurve) CoFactor() *saferith.Nat {
	return saferithUtils.NatOne
}

// === Additive Group Methods.

func (*PallasCurve) Sub(x algebra.AdditiveGroupElement[curves.Curve, curves.Point], ys ...algebra.AdditiveGroupElement[curves.Curve, curves.Point]) curves.Point {
	diff := x
	for _, y := range ys {
		diff = diff.Sub(y)
	}
	return diff.Unwrap()
}

// === Cyclic Group Methods.

func (*PallasCurve) Generator() curves.Point {
	g := new(PallasPoint)
	g.V.SetGenerator()
	return g
}

// === Variety Methods.

func (*PallasCurve) Dimension() int {
	return 1
}

func (*PallasCurve) Discriminant() *saferith.Int {
	result, _ := new(saferith.Nat).SetHex(strings.ToUpper("2a30"))
	return new(saferith.Int).SetNat(result).Neg(1)
}

// === Algebraic Curve Methods.

func (*PallasCurve) BaseField() curves.BaseField {
	return NewPallasBaseField()
}

func (c *PallasCurve) NewPoint(x, y algebra.AlgebraicVarietyBaseFieldElement[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement]) (curves.Point, error) {
	if x == nil || y == nil {
		return nil, errs.NewIsNil("argument is nil")
	}

	xx, ok := x.(*PallasBaseFieldElement)
	if !ok {
		return nil, errs.NewType("x is not the right type")
	}
	yy, ok := y.(*PallasBaseFieldElement)
	if !ok {
		return nil, errs.NewType("y is not the right type")
	}

	if xx.IsZero() && yy.IsZero() {
		return c.AdditiveIdentity(), nil
	}

	value := new(PallasPoint)
	ok2 := value.V.SetAffine(&xx.V, &yy.V)
	if ok2 != 1 {
		return nil, errs.NewCoordinates("could not set x,y")
	}

	return value, nil
}

// === Elliptic Curve Methods.

func (c *PallasCurve) ScalarRing() curves.ScalarField {
	return c.ScalarField()
}

func (*PallasCurve) ScalarField() curves.ScalarField {
	return NewPallasScalarField()
}

func (c *PallasCurve) Point() curves.Point {
	return c.AdditiveIdentity()
}

func (c *PallasCurve) Scalar() curves.Scalar {
	return c.ScalarField().Element()
}

func (c *PallasCurve) BaseFieldElement() curves.BaseFieldElement {
	return c.BaseField().Zero()
}

func (*PallasCurve) FrobeniusEndomorphism(p curves.Point) curves.Point {
	//pp, ok := p.(*PallasPoint)
	//if !ok {
	//	panic("given point is not of the right type")
	//}
	//x := pp.AffineX()
	//y := pp.AffineY()
	//characteristic := NewPallasBaseField().Characteristic()
	//result, err := c.NewPoint(x.Exp(characteristic), y.Exp(characteristic))
	//if err != nil {
	//	panic(errs.WrapFailed(err, "forbenius endomorphism did not succeed"))
	//}
	//return result
	panic("not implemented")
}

func (*PallasCurve) TraceOfFrobenius() *saferith.Int {
	// TODO: find number of rational points
	panic("not implemented.")
}

func (*PallasCurve) JInvariant() *saferith.Int {
	return new(saferith.Int).SetUint64(0)
}

// === Prime SubGroup Methods.

func (*PallasCurve) SubGroupOrder() *saferith.Modulus {
	return pallasOrder
}

func (c *PallasCurve) ScalarBaseMult(sc algebra.ModuleScalar[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar]) curves.Point {
	return c.Generator().ScalarMul(sc)
}

func (*PallasCurve) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	nPoints := make([]pastaImpl.PallasPoint, len(points))
	nScalars := make([][]byte, len(scalars))
	for i, pt := range points {
		ptv, ok := pt.(*PallasPoint)
		if !ok {
			return nil, errs.NewFailed("invalid point type %s, expected PointP256", reflect.TypeOf(pt).Name())
		}
		nPoints[i].Set(&ptv.V)
	}
	for i, sc := range scalars {
		s, ok := sc.(*PallasScalar)
		if !ok {
			return nil, errs.NewFailed("invalid scalar type %s, expected ScalarP256", reflect.TypeOf(sc).Name())
		}
		nScalars[i] = s.V.Bytes()
	}
	value := new(PallasPoint)
	err := pointsImpl.MultiScalarMul[*pastaImpl.Fp](&value.V, nPoints, nScalars)
	if err != nil {
		return nil, errs.WrapFailed(err, "multiscalar multiplication")
	}

	return value, nil
}

func (*PallasCurve) DeriveFromAffineX(x curves.BaseFieldElement) (evenY, oddY curves.Point, err error) {
	xc, ok := x.(*PallasBaseFieldElement)
	if !ok {
		return nil, nil, errs.NewType("provided x coordinate is not a pallas field element")
	}

	p1 := new(PallasPoint)
	p1.V.SetFromAffineX(&xc.V)
	p2 := new(PallasPoint)
	p2.V.Neg(&p1.V)
	if (p1.AffineY().(*PallasBaseFieldElement).V.Bytes()[0] & 0b1) == 0 {
		return p1, p2, nil
	}

	return p2, p1, nil
}

//func PippengerMultiScalarMultPallas(points []*Ep, scalars []*saferith.Nat) *Ep {
//	if len(points) != len(scalars) {
//		return nil
//	}
//
//	const w = 6
//
//	bucketSize := uint64((1 << w) - 1)
//	windows := make([]*Ep, 255/w+1)
//	for i := range windows {
//		windows[i] = new(Ep).Identity()
//	}
//	bucket := make([]*Ep, bucketSize)
//
//	for j := 0; j < len(windows); j++ {
//		for i := uint64(0); i < bucketSize; i++ {
//			bucket[i] = new(Ep).Identity()
//		}
//
//		for i := 0; i < len(scalars); i++ {
//			index := bucketSize & new(saferith.Nat).Rsh(scalars[i], uint(w*j), fp.Modulus.BitLen()).Uint64()
//			if index != 0 {
//				bucket[index-1].Add(bucket[index-1], points[i])
//			}
//		}
//
//		acc, sum := new(Ep).Identity(), new(Ep).Identity()
//
//		for i := int64(bucketSize) - 1; i >= 0; i-- {
//			sum.Add(sum, bucket[i])
//			acc.Add(acc, sum)
//		}
//		windows[j] = acc
//	}
//
//	acc := new(Ep).Identity()
//	for i := len(windows) - 1; i >= 0; i-- {
//		for j := 0; j < w; j++ {
//			acc.Double(acc)
//		}
//		acc.Add(acc, windows[i])
//	}
//	return acc
//}.
