package pasta

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
	pastaImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/pasta/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/traits"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"slices"
	"sync"
)

type (
	PallasBaseFieldElement = FpFieldElement
	PallasScalar           = FqFieldElement
)

const (
	PallasName            = "pallas"
	PallasHash2CurveSuite = "pallas_XMD:BLAKE2b_SSWU_RO_"
)

var (
	pallasInitOnce sync.Once
	pallasInstance *PallasCurve
)

type PallasCurve struct {
	traits.Curve[*pastaImpl.Fp, *pastaImpl.PallasPoint, *PallasPoint, PallasPoint]
}

func NewPallasCurve() *PallasCurve {
	pallasInitOnce.Do(func() {
		pallasInstance = &PallasCurve{}
	})

	return pallasInstance
}

func (c *PallasCurve) Name() string {
	return PallasName
}

func (c *PallasCurve) Order() algebra.Cardinal {
	return fqFieldOrder.Nat()
}

func (c *PallasCurve) Operator() algebra.BinaryOperator[*PallasPoint] {
	return algebra.Add[*PallasPoint]
}

func (c *PallasCurve) FromAffineCompressed(input []byte) (*PallasPoint, error) {
	if len(input) != pastaImpl.FpBytes {
		return nil, errs.NewLength("invalid input")
	}

	sign := input[31] >> 7
	var buffer [pastaImpl.FpBytes]byte
	copy(buffer[:], input)
	buffer[31] &= 0x7f

	var x, y pastaImpl.Fp
	ok := x.SetBytes(buffer[:])
	if ok != 1 {
		return nil, errs.NewLength("invalid input")
	}
	if x.IsZero() == 1 && sign == 0 {
		return c.OpIdentity(), nil
	}

	pp := new(PallasPoint)
	ok = pp.V.SetFromAffineX(&x)
	if ok != 1 {
		return nil, errs.NewLength("invalid input")
	}
	ok = pp.V.ToAffine(&x, &y)
	if ok != 1 {
		panic("this should never happen")
	}

	if (y.Bytes()[0] & 0b1) != sign {
		pp.V.Neg(&pp.V)
	}
	return pp, nil
}

func (c *PallasCurve) FromAffineUncompressed(input []byte) (*PallasPoint, error) {
	if len(input) != 2*pastaImpl.FpBytes {
		return nil, errs.NewLength("invalid input")
	}

	var x, y pastaImpl.Fp
	ok := x.SetBytes(input[:pastaImpl.FpBytes])
	if ok != 1 {
		return nil, errs.NewFailed("invalid input")
	}
	ok = y.SetBytes(input[pastaImpl.FpBytes:])
	if ok != 1 {
		return nil, errs.NewFailed("invalid input")
	}
	if x.IsZero() == 1 && y.IsZero() == 1 {
		return c.OpIdentity(), nil
	}

	pp := new(PallasPoint)
	ok = pp.V.SetAffine(&x, &y)
	if ok != 1 {
		return nil, errs.NewFailed("invalid input")
	}
	return pp, nil
}

func (c *PallasCurve) NewPoint(affineX, affineY *PallasBaseFieldElement) (*PallasPoint, error) {
	//TODO implement me
	panic("implement me")
}

func (c *PallasCurve) Hash(bytes []byte) (*PallasPoint, error) {
	return c.HashWithDst(base.Hash2CurveAppTag+PallasHash2CurveSuite, bytes)
}

func (c *PallasCurve) HashWithDst(dst string, bytes []byte) (*PallasPoint, error) {
	var p PallasPoint
	p.V.Hash(dst, bytes)
	return &p, nil
}

// TODO(aalireza): doesn't make sense of curve/point
func (c *PallasCurve) ElementSize() int {
	//TODO implement me
	panic("implement me")
}

func (c *PallasCurve) WideElementSize() int {
	//TODO implement me
	panic("implement me")
}

func (c *PallasCurve) BasePoints() ds.ImmutableMap[string, *PallasPoint] {
	panic("implement me")
}

func (c *PallasCurve) ScalarField() algebra.PrimeField[*PallasScalar] {
	return NewPallasScalarField()
}

func (c *PallasCurve) BaseField() algebra.FiniteField[*PallasBaseFieldElement] {
	return NewPallasBaseField()
}

type PallasPoint struct {
	traits.Point[*pastaImpl.Fp, *pastaImpl.PallasPoint, pastaImpl.PallasPoint, *PallasPoint, PallasPoint]
}

func (p *PallasPoint) P() *pastaImpl.PallasPoint {
	return &p.V
}

func (p *PallasPoint) HashCode() uint64 {
	//TODO implement me
	panic("implement me")
}

func (p *PallasPoint) Structure() algebra.Structure[*PallasPoint] {
	return NewPallasCurve()
}

func (p *PallasPoint) MarshalBinary() (data []byte, err error) {
	//TODO implement me
	panic("implement me")
}

func (p *PallasPoint) UnmarshalBinary(data []byte) error {
	//TODO implement me
	panic("implement me")
}

// TODO(aalireza): not sure if this should always return affine coordinates or implementation defined coordinates
func (p *PallasPoint) Coordinates() []*PallasBaseFieldElement {
	var x, y FpFieldElement
	p.V.ToAffine(&x.V, &y.V)

	return []*FpFieldElement{&x, &y}
}

func (p *PallasPoint) ToAffineCompressed() []byte {
	// Use ZCash encoding where infinity is all zeros and the top bit represents the sign of y
	// and the remainder represent the x-coordinate
	if p.IsOpIdentity() {
		var zeros [pastaImpl.FpBytes]byte
		return zeros[:]
	}

	var x, y pastaImpl.Fp
	ok := p.V.ToAffine(&x, &y)
	if ok != 1 {
		panic("this should never happen")
	}
	sign := (y.Bytes()[0] & 0b1) << 7
	result := x.Bytes()
	result[31] |= sign
	return result
}

func (p *PallasPoint) ToAffineUncompressed() []byte {
	if p.IsOpIdentity() {
		var zeros [pastaImpl.FpBytes * 2]byte
		return zeros[:]
	}

	var x, y pastaImpl.Fp
	ok := p.V.ToAffine(&x, &y)
	if ok != 1 {
		panic("this should never happen")
	}

	return slices.Concat(x.Bytes(), y.Bytes())
}

func (p *PallasPoint) AffineX() (*PallasBaseFieldElement, error) {
	if p.IsZero() {
		return NewPallasBaseField().One(), nil
	}

	var x, y PallasBaseFieldElement
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		return nil, errs.NewFailed("failed to convert point to affine")
	}

	return &x, nil
}

func (p *PallasPoint) AffineY() (*PallasBaseFieldElement, error) {
	if p.IsZero() {
		return NewPallasBaseField().Zero(), nil
	}

	var x, y PallasBaseFieldElement
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		return nil, errs.NewFailed("failed to convert point to affine")
	}

	return &y, nil
}

func (p *PallasPoint) ScalarMul(actor *PallasScalar) *PallasPoint {
	var result PallasPoint
	pointsImpl.ScalarMul[*pastaImpl.Fp](&result.V, &p.V, actor.V.Bytes())
	return &result
}

func (p *PallasPoint) IsTorsionFree() bool {
	return true
}

func (p *PallasPoint) IsBasePoint(id string) bool {
	//TODO implement me
	panic("implement me")
}

// TODO(aalireza): no use of it
func (p *PallasPoint) CanBeGenerator() bool {
	//TODO implement me
	panic("implement me")
}
