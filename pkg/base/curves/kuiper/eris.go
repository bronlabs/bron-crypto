package kuiper

import (
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/kuiper/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/kuiper/impl/fp"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/kuiper/impl/fq"
	"io"
	"reflect"
	"strings"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/arithmetic/limb7"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/hash2curve"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
	saferithUtils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
)

const ErisName = "Eris" //

var (
	_ curves.Curve = (*Curve)(nil)

	erisInitOnce sync.Once
	erisInstance Curve

	// TODO: how to represent negatives?
	// -0x60000000000030000196800006000065a001ae517fffffffffffffff
	traceOfFrobenius, _ = new(saferith.Nat).SetHex(strings.ToUpper("60000000000030000196800006000065a001ae517fffffffffffffff"))
	jInvariant          = new(saferith.Nat).SetUint64(0).Resize(0)
)

type Curve struct {
	hash2curve.CurveHasher

	_ ds.Incomparable
}

func erisInit() {
	erisInstance = Curve{}
	erisInstance.CurveHasher = hash2curve.NewCurveHasherSha256(
		curves.Curve(&erisInstance),
		base.HASH2CURVE_APP_TAG,
		hash2curve.DstTagSswu,
	)
}

func NewErisCurve() *Curve {
	erisInitOnce.Do(erisInit)
	return &erisInstance
}

// SetHasherAppTag sets the hasher to use for hash-to-curve operations with a
// custom "appTag". Not exposed in the `curves.Curve` interface, as by
// default we should use the library-wide HASH2CURVE_APP_TAG for compatibility.
func (c *Curve) SetHasherAppTag(appTag string) {
	c.CurveHasher = hash2curve.NewCurveHasherSha256(
		curves.Curve(&erisInstance),
		appTag,
		hash2curve.DstTagSswu,
	)
}

func (c *Curve) Cardinality() *saferith.Modulus {
	return c.Order()
}

func (*Curve) Contains(e curves.Point) bool {
	fmt.Println(e.ToAffineCompressed())
	return e.IsInPrimeSubGroup()
}

func (c *Curve) Iter() <-chan curves.Point {
	ch := make(chan curves.Point, 1)
	go func() {
		defer close(ch)
		current := c.Generator()
		ch <- current
		for {
			current = current.Add(c.Generator())
			if current.IsDesignatedGenerator() {
				return
			}
			ch <- current
		}
	}()
	return ch
}

func (*Curve) Operators() []algebra.BinaryOperator[curves.Point] {
	//TODO implement me
	panic("implement me")
}

func (c *Curve) Unwrap() curves.Curve {
	return c
}

func (*Curve) IsDefinedUnder(operator algebra.BinaryOperator[curves.Point]) bool {
	//TODO implement me
	panic("implement me")
}

func (*Curve) Op(operator algebra.BinaryOperator[curves.Point], x algebra.GroupoidElement[curves.Curve, curves.Point], ys ...algebra.GroupoidElement[curves.Curve, curves.Point]) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
}

func (*Curve) Identity(under algebra.BinaryOperator[curves.Point]) (curves.Point, error) {
	//TODO implement me
	panic("implement me")
}

func (*Curve) Addition() algebra.Addition[curves.Point] {
	//TODO implement me
	panic("implement me")
}

func (*Curve) ModuleScalarRing() algebra.ModuleBaseRing[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*Curve) AlgebraicVarietyBaseField() algebra.AlgebraicVarietyBaseField[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*Curve) VectorSpaceScalarField() algebra.VectorSpaceBaseField[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (c *Curve) BasePoint() curves.Point {
	return c.Generator()
}

func (*Curve) DLog(b, x algebra.CyclicGroupElement[curves.Curve, curves.Point], under algebra.BinaryOperator[curves.Point]) (*saferith.Nat, error) {
	//TODO implement me
	panic("implement me")
}

func (c *Curve) SuperGroupOrder() *saferith.Modulus {
	return c.Order()
}

func (*Curve) ElementSize() int {
	panic("implement me")
}

func (*Curve) WideElementSize() int {
	panic("implement me")
}

func (*Curve) Name() string {
	return ErisName
}

func (*Curve) Order() *saferith.Modulus {
	return fq.New().Params.Modulus
}

func (c *Curve) Element() curves.Point {
	return c.AdditiveIdentity()
}

func (c *Curve) Random(prng io.Reader) (curves.Point, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	var seed [base.WideFieldBytes]byte
	if _, err := io.ReadFull(prng, seed[:]); err != nil {
		return nil, errs.WrapRandomSample(err, "cannot read seed")
	}
	return c.Hash(seed[:])
}

func (c *Curve) Hash(input []byte) (curves.Point, error) {
	return c.HashWithDst(input, nil)
}

func (*Curve) HashWithDst(input []byte, dst []byte) (curves.Point, error) {
	p := impl.ErisPointNew()
	u, err := NewErisCurve().HashToFieldElements(2, input, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "hash to field element of Eris failed")
	}
	u0, ok0 := u[0].(*ErisBaseFieldElement)
	u1, ok1 := u[1].(*ErisBaseFieldElement)
	if !ok0 || !ok1 {
		return nil, errs.NewType("Cast to Eris field elements failed")
	}
	err = p.Arithmetic.Map(u0.V, u1.V, p)
	if err != nil {
		return nil, errs.WrapFailed(err, "Map to Eris point failed")
	}
	return &ErisPoint{V: p}, nil
}

func (c *Curve) Select(choice bool, x0, x1 curves.Point) curves.Point {
	x0p, ok0 := x0.(*ErisPoint)
	x1p, ok1 := x1.(*ErisPoint)
	p, okp := c.Element().(*ErisPoint)
	if !ok0 || !ok1 || okp {
		panic("Not an Eris point")
	}
	p.V.X.CMove(x0p.V.X, x1p.V.X, utils.BoolTo[uint64](choice))
	p.V.Y.CMove(x0p.V.Y, x1p.V.Y, utils.BoolTo[uint64](choice))
	p.V.Z.CMove(x0p.V.Z, x1p.V.Z, utils.BoolTo[uint64](choice))
	return p
}

func (*Curve) Add(x algebra.AdditiveGroupoidElement[curves.Curve, curves.Point], ys ...algebra.AdditiveGroupoidElement[curves.Curve, curves.Point]) curves.Point {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum.Unwrap()
}

// === Monoid Methods.

func (*Curve) AdditiveIdentity() curves.Point {
	return &ErisPoint{
		V: impl.ErisPointNew().Identity(),
	}
}

func (*Curve) CoFactor() *saferith.Nat {
	return saferithUtils.NatOne
}

func (*Curve) Sub(x algebra.AdditiveGroupElement[curves.Curve, curves.Point], ys ...algebra.AdditiveGroupElement[curves.Curve, curves.Point]) curves.Point {
	diff := x
	for _, y := range ys {
		diff = diff.Sub(y)
	}
	return diff.Unwrap()
}

func (*Curve) Generator() curves.Point {
	return &ErisPoint{
		V: impl.ErisPointNew().Generator(),
	}
}

func (*Curve) Dimension() int {
	return 1
}

func (*Curve) Discriminant() *saferith.Int {
	result, _ := new(saferith.Nat).SetHex(strings.ToUpper("fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffa97f"))
	return new(saferith.Int).SetNat(result)
}

// === Algebraic Curve Methods.

func (*Curve) BaseField() curves.BaseField {
	return NewErisBaseField()
}

func (*Curve) NewPoint(x, y algebra.AlgebraicVarietyBaseFieldElement[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement]) (curves.Point, error) {
	if x == nil || y == nil {
		return nil, errs.NewIsNil("argument is nil")
	}
	xx, ok := x.Unwrap().(*ErisBaseFieldElement)
	if !ok {
		return nil, errs.NewType("x is not the right type")
	}
	yy, ok := y.Unwrap().(*ErisBaseFieldElement)
	if !ok {
		return nil, errs.NewType("y is not the right type")
	}
	value, err := impl.ErisPointNew().SetNat(xx.Nat(), yy.Nat())
	if err != nil {
		return nil, errs.WrapCoordinates(err, "could not set x,y")
	}
	return &ErisPoint{V: value}, nil
}

// === Elliptic Curve Methods.

func (*Curve) ScalarField() curves.ScalarField {
	return NewErisScalarField()
}

func (c *Curve) ScalarRing() curves.ScalarField {
	return c.ScalarField()
}

func (c *Curve) Point() curves.Point {
	return c.AdditiveIdentity()
}

func (c *Curve) Scalar() curves.Scalar {
	return c.ScalarField().AdditiveIdentity()
}

func (c *Curve) BaseFieldElement() curves.BaseFieldElement {
	return c.BaseField().Zero()
}

func (c *Curve) FrobeniusEndomorphism(p curves.Point) curves.Point {
	pp, ok := p.(*ErisPoint)
	if !ok {
		panic("given point is not of the right type")
	}
	x := pp.AffineX()
	y := pp.AffineY()
	characteristic := NewBaseFieldElement(0).SetNat(NewErisBaseField().Characteristic())
	result, err := c.NewPoint(x.Exp(characteristic.Nat()), y.Exp(characteristic.Nat()))
	if err != nil {
		panic(errs.WrapFailed(err, "frobenius endomorphism did not succeed"))
	}
	return result
}

func (*Curve) TraceOfFrobenius() *saferith.Int {
	return new(saferith.Int).SetNat(traceOfFrobenius)
}

func (*Curve) JInvariant() *saferith.Int {
	return new(saferith.Int).SetNat(jInvariant)
}

// === Prime SubGroup Methods.

func (*Curve) SubGroupOrder() *saferith.Modulus {
	return fp.NewFp().Params.Modulus
}

func (c *Curve) ScalarBaseMult(sc algebra.ModuleScalar[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar]) curves.Point {
	return c.Generator().ScalarMul(sc)
}

func (*Curve) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	nPoints := make([]*limb7.EllipticPoint, len(points))
	nScalars := make([]*limb7.FieldValue, len(scalars))
	for i, pt := range points {
		ptv, ok := pt.(*ErisPoint)
		if !ok {
			return nil, errs.NewFailed("invalid point type %s, expected Eris point", reflect.TypeOf(pt).Name())
		}
		nPoints[i] = ptv.V
	}
	for i, sc := range scalars {
		s, ok := sc.(*ErisScalar)
		if !ok {
			return nil, errs.NewFailed("invalid scalar type %s, expected Eris point", reflect.TypeOf(sc).Name())
		}
		nScalars[i] = s.V
	}
	value := impl.ErisPointNew()
	_, err := value.SumOfProducts(nPoints, nScalars)
	if err != nil {
		return nil, errs.WrapFailed(err, "multiscalar multiplication")
	}
	return &ErisPoint{V: value}, nil
}

func (*Curve) DeriveFromAffineX(x curves.BaseFieldElement) (evenY, oddY curves.Point, err error) {
	xc, ok := x.(*ErisBaseFieldElement)
	if !ok {
		return nil, nil, errs.NewType("provided x coordinate is not a Eris field element")
	}
	rhs := fq.New()
	cPoint := new(ErisPoint)
	cPoint.V = impl.ErisPointNew()
	cPoint.V.Arithmetic.RhsEquation(rhs, xc.V)
	y, wasQr := fp.NewFp().Sqrt(rhs)
	if !wasQr {
		return nil, nil, errs.NewCoordinates("x was not a quadratic residue")
	}
	p1e := impl.ErisPointNew().Identity()
	p1e.X = xc.V
	p1e.Y = fq.New().Set(y)
	p1e.Z.SetOne()

	p2e := impl.ErisPointNew().Identity()
	p2e.X = xc.V
	p2e.Y = fq.New().Neg(fq.New().Set(y))
	p2e.Z.SetOne()

	p1 := &ErisPoint{V: p1e}
	p2 := &ErisPoint{V: p2e}

	if p1.AffineY().IsEven() {
		return p1, p2, nil
	}
	return p2, p1, nil
}
