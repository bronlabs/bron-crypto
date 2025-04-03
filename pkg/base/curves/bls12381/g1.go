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
	CurveNameG1       = "BLS12381G1"
	Hash2CurveSuiteG1 = "BLS12381G1_XMD:SHA-256_SSWU_RO_"
)

var (
	_ curves.Curve[*PointG1, *BaseFieldElementG1, *Scalar] = (*CurveG1)(nil)
	_ curves.Point[*PointG1, *BaseFieldElementG1, *Scalar] = (*PointG1)(nil)

	curveInstanceG1 *CurveG1
	curveInitOnceG1 sync.Once
)

type CurveG1 struct {
	traits.CurveTrait[*bls12381Impl.Fp, *bls12381Impl.G1Point, *PointG1, PointG1]
}

func NewG1Curve() *CurveG1 {
	curveInitOnceG1.Do(func() {
		curveInstanceG1 = &CurveG1{}
	})

	return curveInstanceG1
}

func (c *CurveG1) Name() string {
	return CurveNameG1
}

func (c *CurveG1) Order() algebra.Cardinal {
	return scalarFieldOrder.Nat()
}

func (c *CurveG1) Operator() algebra.BinaryOperator[*PointG1] {
	return algebra.Add[*PointG1]
}

func (c *CurveG1) FromAffineCompressed(input []byte) (*PointG1, error) {
	if len(input) != bls12381Impl.FpBytes {
		return nil, errs.NewLength("invalid input")
	}

	var xFp, yFp, yNegFp bls12381Impl.Fp
	var xBytes [bls12381Impl.FpBytes]byte
	pp := new(PointG1)
	compressedFlag := uint64((input[0] >> 7) & 1)
	infinityFlag := uint64((input[0] >> 6) & 1)
	sortFlag := uint64((input[0] >> 5) & 1)

	if compressedFlag != 1 {
		return nil, errs.NewFailed("compressed flag must be set")
	}

	if infinityFlag == 1 {
		if sortFlag == 1 {
			return nil, errs.NewFailed("infinity flag and sort flag are both set")
		}
		pp.V.SetIdentity()
		return pp, nil
	}

	copy(xBytes[:], input)
	// Mask away the flag bits
	xBytes[0] &= 0x1f
	slices.Reverse(xBytes[:])
	if valid := xFp.SetBytes(xBytes[:]); valid != 1 {
		return nil, errs.NewFailed("invalid bytes - not in field")
	}

	if wasSquare := pp.V.SetFromAffineX(&xFp); wasSquare != 1 {
		return nil, errs.NewFailed("point is not on the curve")
	}
	if ok := pp.V.ToAffine(&xFp, &yFp); ok != 1 {
		panic("this should never happen")
	}

	yNegFp.Neg(&pp.V.Y)
	pp.V.Y.Select(fieldsImpl.IsNegative(&yFp)^sortFlag, &pp.V.Y, &yNegFp)

	if !pp.IsTorsionFree() {
		return nil, errs.NewFailed("point is not in correct subgroup")
	}

	return pp, nil
}

func (c *CurveG1) FromAffineUncompressed(input []byte) (*PointG1, error) {
	if len(input) != 2*bls12381Impl.FpBytes {
		return nil, errs.NewLength("invalid input")
	}

	var xFp, yFp bls12381Impl.Fp
	var t [2 * bls12381Impl.FpBytes]byte
	pp := new(PointG1)
	infinityFlag := uint64((input[0] >> 6) & 1)

	if infinityFlag == 1 {
		pp.V.SetIdentity()
		return pp, nil
	}

	copy(t[:], input)
	// Mask away top bits
	t[0] &= 0x1f
	xBytes := t[:bls12381Impl.FpBytes]
	slices.Reverse(xBytes)
	yBytes := t[bls12381Impl.FpBytes:]
	slices.Reverse(yBytes)

	if valid := xFp.SetBytes(xBytes); valid != 1 {
		return nil, errs.NewFailed("invalid bytes - x not in field")
	}
	if valid := yFp.SetBytes(yBytes); valid != 1 {
		return nil, errs.NewFailed("invalid bytes - y not in field")
	}
	if valid := pp.V.SetAffine(&xFp, &yFp); valid != 1 {
		return nil, errs.NewFailed("point is not on the curve")
	}
	if !pp.IsTorsionFree() {
		return nil, errs.NewFailed("point is not in correct subgroup")
	}

	return pp, nil
}

func (c *CurveG1) NewPoint(affineX, affineY *BaseFieldElementG1) (*PointG1, error) {
	//TODO implement me
	panic("implement me")
}

func (c *CurveG1) Hash(bytes []byte) (*PointG1, error) {
	return c.HashWithDst(base.Hash2CurveAppTag+Hash2CurveSuiteG1, bytes)
}

func (c *CurveG1) HashWithDst(dst string, bytes []byte) (*PointG1, error) {
	var p PointG1
	p.V.Hash(dst, bytes)
	return &p, nil
}

// TODO(aalireza): doesn't make sense of curve/point
func (c *CurveG1) ElementSize() int {
	//TODO implement me
	panic("implement me")
}

func (c *CurveG1) WideElementSize() int {
	//TODO implement me
	panic("implement me")
}

func (c *CurveG1) BasePoints() ds.ImmutableMap[string, *PointG1] {
	panic("implement me")
}

func (c *CurveG1) ScalarField() algebra.PrimeField[*Scalar] {
	return NewScalarField()
}

func (c *CurveG1) BaseField() algebra.FiniteField[*BaseFieldElementG1] {
	return NewG1BaseField()
}

type PointG1 struct {
	traits.PointTrait[*bls12381Impl.Fp, *bls12381Impl.G1Point, bls12381Impl.G1Point, *PointG1, PointG1]
}

func (p *PointG1) HashCode() uint64 {
	//TODO implement me
	panic("implement me")
}

func (p *PointG1) Structure() algebra.Structure[*PointG1] {
	return NewG1Curve()
}

func (p *PointG1) MarshalBinary() (data []byte, err error) {
	//TODO implement me
	panic("implement me")
}

func (p *PointG1) UnmarshalBinary(data []byte) error {
	//TODO implement me
	panic("implement me")
}

// TODO(aalireza): not sure if this should always return affine coordinates or implementation defined coordinates
func (p *PointG1) Coordinates() []*BaseFieldElementG1 {
	var x, y BaseFieldElementG1
	p.V.ToAffine(&x.V, &y.V)

	return []*BaseFieldElementG1{&x, &y}
}

func (p *PointG1) ToAffineCompressed() []byte {
	var x, y bls12381Impl.Fp
	x.SetZero()
	y.SetZero()
	p.V.ToAffine(&x, &y)

	bitC := uint64(1)
	bitI := p.V.IsIdentity()
	bitS := fieldsImpl.IsNegative(&y) & (bitI ^ 1)
	m := byte((bitC << 7) | (bitI << 6) | (bitS << 5))

	xBytes := x.Bytes()
	slices.Reverse(xBytes)
	xBytes[0] |= m
	return xBytes
}

func (p *PointG1) ToAffineUncompressed() []byte {
	var x, y bls12381Impl.Fp
	x.SetZero()
	y.SetZero()
	p.V.ToAffine(&x, &y)

	bitC := uint64(0)
	bitI := p.V.IsIdentity()
	bitS := uint64(0)
	m := byte((bitC << 7) | (bitI << 6) | (bitS << 5))

	xBytes := x.Bytes()
	slices.Reverse(xBytes)
	yBytes := y.Bytes()
	slices.Reverse(yBytes)

	result := slices.Concat(xBytes, yBytes)
	result[0] |= m
	return result
}

func (p *PointG1) AffineX() *BaseFieldElementG1 {
	if p.IsZero() {
		return NewG1BaseField().One()
	}

	var x, y BaseFieldElementG1
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		panic("this should never happen - failed to convert point to affine")
	}

	return &x
}

func (p *PointG1) AffineY() *BaseFieldElementG1 {
	if p.IsZero() {
		return NewG1BaseField().Zero()
	}

	var x, y BaseFieldElementG1
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		panic("this should never happen - failed to convert point to affine")
	}

	return &y
}

func (p *PointG1) ScalarMul(actor *Scalar) *PointG1 {
	var result PointG1
	pointsImpl.ScalarMul[*bls12381Impl.Fp](&result.V, &p.V, actor.V.Bytes())
	return &result
}

func (p *PointG1) IsTorsionFree() bool {
	orderBytes := scalarFieldOrder.Bytes()
	slices.Reverse(orderBytes)
	var e bls12381Impl.G1Point
	pointsImpl.ScalarMul[*bls12381Impl.Fp](&e, &p.V, orderBytes)
	return e.IsIdentity() == 1
}

func (p *PointG1) IsBasePoint(id string) bool {
	//TODO implement me
	panic("implement me")
}

// TODO(aalireza): no use of it
func (p *PointG1) CanBeGenerator() bool {
	//TODO implement me
	panic("implement me")
}
