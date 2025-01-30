package pasta

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/bitstring"
	"io"
	"iter"
	"reflect"
	"strings"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/krypton-primitives/pkg/base"
	"github.com/bronlabs/krypton-primitives/pkg/base/algebra"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/h2c"
	pointsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/points"
	pastaImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/pasta/impl"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	saferithUtils "github.com/bronlabs/krypton-primitives/pkg/base/utils/saferith"
)

const (
	VestaName                  = "vesta"
	VestaHash2CurveSuite       = "vesta_XMD:BLAKE2b_SSWU_RO_"
	VestaHash2CurveScalarSuite = "vesta_XMD:BLAKE2b_SSWU_RO_SC_"
)

var (
	vestaInitOnce sync.Once
	vestaInstance VestaCurve
	vestaOrder    *saferith.Modulus
)

var _ curves.Curve = (*VestaCurve)(nil)

type VestaCurve struct {
	_ ds.Incomparable
}

func vestaInit() {
	vestaOrder = saferith.ModulusFromBytes(bitstring.ReverseBytes(pastaImpl.FpModulus[:]))

	vestaInstance = VestaCurve{}
}

func NewVestaCurve() *VestaCurve {
	vestaInitOnce.Do(vestaInit)
	return &vestaInstance
}

func (*VestaCurve) HashToFieldElements(count int, dstPrefix string, msg []byte) (u []curves.BaseFieldElement, err error) {
	out := make([]pastaImpl.Fq, count)
	h2c.HashToField(out[:], pastaImpl.VestaCurveHasherParams{}, dstPrefix+VestaHash2CurveSuite, msg)

	u = make([]curves.BaseFieldElement, count)
	for i := range out {
		v := new(VestaBaseFieldElement)
		v.V.Set(&out[i])
		u[i] = v
	}

	return u, nil
}

func (*VestaCurve) HashToScalars(count int, dstPrefix string, msg []byte) (u []curves.Scalar, err error) {
	out := make([]pastaImpl.Fp, count)
	h2c.HashToField(out[:], pastaImpl.VestaCurveHasherParams{}, dstPrefix+VestaHash2CurveScalarSuite, msg)

	u = make([]curves.Scalar, count)
	for i := range out {
		v := new(VestaScalar)
		v.V.Set(&out[i])
		u[i] = v
	}

	return u, nil
}

func (*VestaCurve) Cardinality() *saferith.Nat {
	//TODO implement me
	panic("implement me")
}

func (*VestaCurve) Contains(e curves.Point) bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaCurve) Iter() iter.Seq[curves.Point] {
	//TODO implement me
	panic("implement me")
}

func (*VestaCurve) Operators() []algebra.BinaryOperator[curves.Point] {
	//TODO implement me
	panic("implement me")
}

func (c *VestaCurve) Unwrap() curves.Curve {
	return c
}

func (*VestaCurve) IsDefinedUnder(operator algebra.BinaryOperator[curves.Point]) bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaCurve) Op(operator algebra.BinaryOperator[curves.Point], x algebra.GroupoidElement[curves.Curve, curves.Point], ys ...algebra.GroupoidElement[curves.Curve, curves.Point]) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaCurve) Addition() algebra.Addition[curves.Point] {
	//TODO implement me
	panic("implement me")
}

func (*VestaCurve) ModuleScalarRing() algebra.ModuleBaseRing[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*VestaCurve) AlgebraicVarietyBaseField() algebra.AlgebraicVarietyBaseField[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*VestaCurve) VectorSpaceScalarField() algebra.VectorSpaceBaseField[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (c *VestaCurve) BasePoint() curves.Point {
	return c.Generator()
}

func (*VestaCurve) DLog(b, x algebra.CyclicGroupElement[curves.Curve, curves.Point], under algebra.BinaryOperator[curves.Point]) (*saferith.Nat, error) {
	//TODO implement me
	panic("implement me")
}

func (c *VestaCurve) SuperGroupOrder() *saferith.Modulus {
	return c.Order()
}

func (*VestaCurve) ElementSize() int {
	return pastaImpl.FqBytes
}

func (*VestaCurve) WideElementSize() int {
	return pastaImpl.FqWideBytes
}

func (*VestaCurve) Name() string {
	return VestaName
}

func (c *VestaCurve) Order() *saferith.Modulus {
	return c.SubGroupOrder()
}

func (c *VestaCurve) Element() curves.Point {
	return c.AdditiveIdentity()
}

func (*VestaCurve) Random(prng io.Reader) (curves.Point, error) {
	p := new(VestaPoint)
	ok := p.V.SetRandom(prng)
	if ok != 1 {
		return nil, errs.NewRandomSample("vesta point")
	}

	return p, nil
}

func (c *VestaCurve) Hash(input []byte) (curves.Point, error) {
	return c.HashWithDst(base.Hash2CurveAppTag+VestaHash2CurveSuite, input)
}

func (*VestaCurve) HashWithDst(dst string, input []byte) (curves.Point, error) {
	p := new(VestaPoint)
	p.V.Hash(dst, input)
	return p, nil
}

func (*VestaCurve) Select(choice uint64, x0, x1 curves.Point) curves.Point {
	x0p, ok0 := x0.(*VestaPoint)
	if !ok0 {
		panic("x0 is not a non-empty Vesta point")
	}
	x1p, ok1 := x1.(*VestaPoint)
	if !ok1 {
		panic("x1 is not a non-empty Vesta point")
	}

	p := new(VestaPoint)
	p.V.Select(choice, &x0p.V, &x1p.V)
	return p
}

// === Additive Groupoid Methods.

func (*VestaCurve) Add(x algebra.AdditiveGroupoidElement[curves.Curve, curves.Point], ys ...algebra.AdditiveGroupoidElement[curves.Curve, curves.Point]) curves.Point {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum.Unwrap()
}

// === Monoid Methods.

func (*VestaCurve) Identity(under algebra.BinaryOperator[curves.Point]) (curves.Point, error) {
	panic("implement me")
}

// === Additive Monoid Methods.

func (*VestaCurve) AdditiveIdentity() curves.Point {
	id := new(VestaPoint)
	id.V.SetIdentity()
	return id
}

// === Group Methods.

func (*VestaCurve) CoFactor() *saferith.Nat {
	return saferithUtils.NatOne
}

// === Additive Group Methods.

func (*VestaCurve) Sub(x algebra.AdditiveGroupElement[curves.Curve, curves.Point], ys ...algebra.AdditiveGroupElement[curves.Curve, curves.Point]) curves.Point {
	diff := x
	for _, y := range ys {
		diff = diff.Sub(y)
	}
	return diff.Unwrap()
}

// === Cyclic Group Methods.

func (*VestaCurve) Generator() curves.Point {
	g := new(VestaPoint)
	g.V.SetGenerator()
	return g
}

// === Variety Methods.

func (*VestaCurve) Dimension() int {
	return 1
}

func (*VestaCurve) Discriminant() *saferith.Int {
	result, _ := new(saferith.Nat).SetHex(strings.ToUpper("2a30"))
	return new(saferith.Int).SetNat(result).Neg(1)
}

// === Algebraic Curve Methods.

func (*VestaCurve) BaseField() curves.BaseField {
	return NewVestaBaseField()
}

func (c *VestaCurve) NewPoint(x, y algebra.AlgebraicVarietyBaseFieldElement[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement]) (curves.Point, error) {
	if x == nil || y == nil {
		return nil, errs.NewIsNil("argument is nil")
	}

	xx, ok := x.(*VestaBaseFieldElement)
	if !ok {
		return nil, errs.NewType("x is not the right type")
	}
	yy, ok := y.(*VestaBaseFieldElement)
	if !ok {
		return nil, errs.NewType("y is not the right type")
	}

	if xx.IsZero() && yy.IsZero() {
		return c.AdditiveIdentity(), nil
	}

	value := new(VestaPoint)
	ok2 := value.V.SetAffine(&xx.V, &yy.V)
	if ok2 != 1 {
		return nil, errs.NewCoordinates("could not set x,y")
	}

	return value, nil
}

// === Elliptic Curve Methods.

func (c *VestaCurve) ScalarRing() curves.ScalarField {
	return c.ScalarField()
}

func (*VestaCurve) ScalarField() curves.ScalarField {
	return NewVestaScalarField()
}

func (c *VestaCurve) Point() curves.Point {
	return c.AdditiveIdentity()
}

func (c *VestaCurve) Scalar() curves.Scalar {
	return c.ScalarField().Element()
}

func (c *VestaCurve) BaseFieldElement() curves.BaseFieldElement {
	return c.BaseField().Zero()
}

func (*VestaCurve) FrobeniusEndomorphism(p curves.Point) curves.Point {
	panic("not implemented")
}

func (*VestaCurve) TraceOfFrobenius() *saferith.Int {
	// TODO: find number of rational points
	panic("not implemented.")
}

func (*VestaCurve) JInvariant() *saferith.Int {
	return new(saferith.Int).SetUint64(0)
}

// === Prime SubGroup Methods.

func (*VestaCurve) SubGroupOrder() *saferith.Modulus {
	return vestaOrder
}

func (c *VestaCurve) ScalarBaseMult(sc algebra.ModuleScalar[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar]) curves.Point {
	return c.Generator().ScalarMul(sc)
}

func (*VestaCurve) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	nPoints := make([]pastaImpl.VestaPoint, len(points))
	nScalars := make([][]byte, len(scalars))
	for i, pt := range points {
		ptv, ok := pt.(*VestaPoint)
		if !ok {
			return nil, errs.NewFailed("invalid point type %s, expected PointP256", reflect.TypeOf(pt).Name())
		}
		nPoints[i].Set(&ptv.V)
	}
	for i, sc := range scalars {
		s, ok := sc.(*VestaScalar)
		if !ok {
			return nil, errs.NewFailed("invalid scalar type %s, expected ScalarP256", reflect.TypeOf(sc).Name())
		}
		nScalars[i] = s.V.Bytes()
	}
	value := new(VestaPoint)
	err := pointsImpl.MultiScalarMul[*pastaImpl.Fq](&value.V, nPoints, nScalars)
	if err != nil {
		return nil, errs.WrapFailed(err, "multiscalar multiplication")
	}

	return value, nil
}

func (*VestaCurve) DeriveFromAffineX(x curves.BaseFieldElement) (evenY, oddY curves.Point, err error) {
	xc, ok := x.(*VestaBaseFieldElement)
	if !ok {
		return nil, nil, errs.NewType("provided x coordinate is not a vesta field element")
	}

	p1 := new(VestaPoint)
	p1.V.SetFromAffineX(&xc.V)
	p2 := new(VestaPoint)
	p2.V.Neg(&p1.V)
	if (p1.AffineY().(*VestaBaseFieldElement).V.Bytes()[0] & 0b1) == 0 {
		return p1, p2, nil
	}

	return p2, p1, nil
}
