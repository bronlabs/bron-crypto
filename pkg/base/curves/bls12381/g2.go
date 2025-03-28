package bls12381

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	bls12381Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381/impl"
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/fields"
	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/traits"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"slices"
	"sync"
)

const (
	CurveNameG2       = "BLS12381G2"
	Hash2CurveSuiteG2 = "BLS12381G2_XMD:SHA-256_SSWU_RO_"
)

var (
	_ curves.Curve[*PointG2, *BaseFieldElementG2, *Scalar] = (*CurveG2)(nil)
	_ curves.Point[*PointG2, *BaseFieldElementG2, *Scalar] = (*PointG2)(nil)

	curveInstanceG2 *CurveG2
	curveInitOnceG2 sync.Once
)

type CurveG2 struct {
	traits.Curve[*bls12381Impl.Fp2, *bls12381Impl.G2Point, *PointG2, PointG2]
}

func NewG2Curve() *CurveG2 {
	curveInitOnceG2.Do(func() {
		curveInstanceG2 = &CurveG2{}
	})

	return curveInstanceG2
}

func (c *CurveG2) Name() string {
	return CurveNameG2
}

func (c *CurveG2) Order() algebra.Cardinal {
	return scalarFieldOrder.Nat()
}

func (c *CurveG2) Operator() algebra.BinaryOperator[*PointG2] {
	return algebra.Add[*PointG2]
}

func (c *CurveG2) FromAffineCompressed(input []byte) (*PointG2, error) {
	if len(input) != 2*bls12381Impl.FpBytes {
		return nil, errs.NewLength("invalid input")
	}

	var buffer [2 * bls12381Impl.FpBytes]byte
	copy(buffer[:], input)

	result := new(PointG2)
	compressedFlag := uint64((buffer[0] >> 7) & 1)
	infinityFlag := uint64((buffer[0] >> 6) & 1)
	sortFlag := uint64((buffer[0] >> 5) & 1)
	if compressedFlag != 1 {
		return nil, errs.NewFailed("compressed flag must be set")
	}
	if infinityFlag == 1 {
		if sortFlag == 1 {
			return nil, errs.NewFailed("infinity flag and sort flag are both set")
		}
		result.V.SetIdentity()
		return result, nil
	}

	buffer[0] &= 0x1f
	x1Bytes := buffer[:bls12381Impl.FpBytes]
	slices.Reverse(x1Bytes)
	x0Bytes := buffer[bls12381Impl.FpBytes : 2*bls12381Impl.FpBytes]
	slices.Reverse(x0Bytes)

	var x, y, yNeg bls12381Impl.Fp2
	if ok := x.U1.SetBytes(x1Bytes); ok != 1 {
		return nil, errs.NewFailed("x is not an Fp2")
	}
	if ok := x.U0.SetBytes(x0Bytes); ok != 1 {
		return nil, errs.NewFailed("x is not an Fp2")
	}

	// Recover a y-coordinate given x by y = sqrt(x^3 + 4)
	pp := new(PointG2)
	if wasSquare := pp.V.SetFromAffineX(&x); wasSquare != 1 {
		return nil, errs.NewFailed("point is not on the curve")
	}
	pp.V.ToAffine(&x, &y)
	yNeg.Neg(&pp.V.Y)
	pp.V.Y.Select(isNegative(&y)^sortFlag, &pp.V.Y, &yNeg)

	if !pp.IsTorsionFree() {
		return nil, errs.NewFailed("point is not in correct subgroup")
	}
	return pp, nil
}

func (c *CurveG2) FromAffineUncompressed(input []byte) (*PointG2, error) {
	if len(input) != 4*bls12381Impl.FpBytes {
		return nil, errs.NewLength("invalid input")
	}

	var buffer [4 * bls12381Impl.FpBytes]byte
	copy(buffer[:], input)
	pp := new(PointG2)

	infinityFlag := uint64((input[0] >> 6) & 1)
	if infinityFlag == 1 {
		pp.V.SetIdentity()
		return pp, nil
	}

	// Mask away top bits
	buffer[0] &= 0x1f
	x1Bytes := buffer[:bls12381Impl.FpBytes]
	slices.Reverse(x1Bytes)
	x0Bytes := buffer[bls12381Impl.FpBytes : 2*bls12381Impl.FpBytes]
	slices.Reverse(x0Bytes)
	y1Bytes := buffer[2*bls12381Impl.FpBytes : 3*bls12381Impl.FpBytes]
	slices.Reverse(y1Bytes)
	y0Bytes := buffer[3*bls12381Impl.FpBytes:]
	slices.Reverse(y0Bytes)

	var x, y bls12381Impl.Fp2
	if ok := x.U1.SetBytes(x1Bytes); ok != 1 {
		return nil, errs.NewFailed("x is not an Fp2")
	}
	if ok := x.U0.SetBytes(x0Bytes); ok != 1 {
		return nil, errs.NewFailed("x is not an Fp2")
	}
	if ok := y.U1.SetBytes(y1Bytes); ok != 1 {
		return nil, errs.NewFailed("y is not an Fp2")
	}
	if ok := y.U0.SetBytes(y0Bytes); ok != 1 {
		return nil, errs.NewFailed("y is not an Fp2")
	}
	if valid := pp.V.SetAffine(&x, &y); valid != 1 {
		return nil, errs.NewFailed("point is not on the curve")
	}
	if !pp.IsTorsionFree() {
		return nil, errs.NewFailed("point is not in correct subgroup")
	}

	return pp, nil
}

func (c *CurveG2) NewPoint(affineX, affineY *BaseFieldElementG2) (*PointG2, error) {
	//TODO implement me
	panic("implement me")
}

func (c *CurveG2) Hash(bytes []byte) (*PointG2, error) {
	return c.HashWithDst(base.Hash2CurveAppTag+Hash2CurveSuiteG2, bytes)
}

func (c *CurveG2) HashWithDst(dst string, bytes []byte) (*PointG2, error) {
	var p PointG2
	p.V.Hash(dst, bytes)
	return &p, nil
}

// TODO(aalireza): doesn't make sense of curve/point
func (c *CurveG2) ElementSize() int {
	//TODO implement me
	panic("implement me")
}

func (c *CurveG2) WideElementSize() int {
	//TODO implement me
	panic("implement me")
}

func (c *CurveG2) BasePoints() ds.ImmutableMap[string, *PointG2] {
	panic("implement me")
}

func (c *CurveG2) ScalarField() algebra.PrimeField[*Scalar] {
	return NewScalarField()
}

type PointG2 struct {
	traits.Point[*bls12381Impl.Fp2, *bls12381Impl.G2Point, bls12381Impl.G2Point, *PointG2, PointG2]
}

func (p *PointG2) P() *bls12381Impl.G2Point {
	return &p.V
}

func (p *PointG2) HashCode() uint64 {
	//TODO implement me
	panic("implement me")
}

func (p *PointG2) Structure() algebra.Structure[*PointG2] {
	return NewG2Curve()
}

func (p *PointG2) MarshalBinary() (data []byte, err error) {
	//TODO implement me
	panic("implement me")
}

func (p *PointG2) UnmarshalBinary(data []byte) error {
	//TODO implement me
	panic("implement me")
}

// TODO(aalireza): not sure if this should always return affine coordinates or implementation defined coordinates
func (p *PointG2) Coordinates() []*BaseFieldElementG2 {
	var x, y BaseFieldElementG2
	p.V.ToAffine(&x.V, &y.V)

	return []*BaseFieldElementG2{&x, &y}
}

func (p *PointG2) ToAffineCompressed() []byte {
	var x, y bls12381Impl.Fp2
	x.SetZero()
	y.SetZero()
	p.V.ToAffine(&x, &y)
	isInfinity := p.V.IsIdentity()

	x1Bytes := x.U1.Bytes()
	slices.Reverse(x1Bytes)
	x0Bytes := x.U0.Bytes()
	slices.Reverse(x0Bytes)

	out := slices.Concat(x1Bytes, x0Bytes)
	// Compressed flag
	out[0] |= 1 << 7
	// Is infinity
	out[0] |= byte(isInfinity << 6)
	// Sign of y only set if not infinity
	out[0] |= byte((isNegative(&y) & (isInfinity ^ 1)) << 5)
	return out
}

func (p *PointG2) ToAffineUncompressed() []byte {
	var x, y bls12381Impl.Fp2
	x.SetZero()
	y.SetZero()
	isInfinity := p.V.IsIdentity()
	p.V.ToAffine(&x, &y)

	x1Bytes := x.U1.Bytes()
	slices.Reverse(x1Bytes[:])
	x0Bytes := x.U0.Bytes()
	slices.Reverse(x0Bytes[:])
	y1Bytes := y.U1.Bytes()
	slices.Reverse(y1Bytes[:])
	y0Bytes := y.U0.Bytes()
	slices.Reverse(y0Bytes[:])

	out := slices.Concat(x1Bytes, x0Bytes, y1Bytes, y0Bytes)
	out[0] |= byte(isInfinity << 6)
	return out
}

func (p *PointG2) AffineX() (*BaseFieldElementG2, error) {
	var x, y BaseFieldElementG2
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		return nil, errs.NewFailed("failed to convert point to affine")
	}

	return &x, nil
}

func (p *PointG2) AffineY() (*BaseFieldElementG2, error) {
	var x, y BaseFieldElementG2
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		return nil, errs.NewFailed("failed to convert point to affine")
	}

	return &y, nil
}

func (p *PointG2) ScalarMul(actor *Scalar) *PointG2 {
	var result PointG2
	pointsImpl.ScalarMul[*bls12381Impl.Fp2](&result.V, &p.V, actor.V.Bytes())
	return &result
}

func (p *PointG2) IsTorsionFree() bool {
	orderBytes := scalarFieldOrder.Bytes()
	slices.Reverse(orderBytes)
	var e bls12381Impl.G2Point
	pointsImpl.ScalarMul[*bls12381Impl.Fp2](&e, &p.V, orderBytes)
	return e.IsIdentity() == 1
}

func (p *PointG2) IsBasePoint(id string) bool {
	//TODO implement me
	panic("implement me")
}

// TODO(aalireza): no use of it
func (p *PointG2) CanBeGenerator() bool {
	//TODO implement me
	panic("implement me")
}

func isNegative(v *bls12381Impl.Fp2) uint64 {
	c1Neg := fieldsImpl.IsNegative(&v.U1)
	c0Neg := fieldsImpl.IsNegative(&v.U0)
	c1Zero := v.U1.IsZero()

	return c1Neg | (c1Zero & c0Neg)
}
