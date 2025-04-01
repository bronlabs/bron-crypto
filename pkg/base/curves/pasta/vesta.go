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
	VestaBaseFieldElement = FqFieldElement
	VestaScalar           = FpFieldElement
)

const (
	VestaName            = "vesta"
	VestaHash2CurveSuite = "vesta_XMD:BLAKE2b_SSWU_RO_"
)

var (
	vestaInitOnce sync.Once
	vestaInstance *VestaCurve
)

type VestaCurve struct {
	traits.Curve[*pastaImpl.Fq, *pastaImpl.VestaPoint, *VestaPoint, VestaPoint]
}

func NewVestaCurve() *VestaCurve {
	vestaInitOnce.Do(func() {
		vestaInstance = &VestaCurve{}
	})

	return vestaInstance
}

func (c *VestaCurve) Name() string {
	return VestaName
}

func (c *VestaCurve) Order() algebra.Cardinal {
	return fpFieldOrder.Nat()
}

func (c *VestaCurve) Operator() algebra.BinaryOperator[*VestaPoint] {
	return algebra.Add[*VestaPoint]
}

func (c *VestaCurve) FromAffineCompressed(input []byte) (*VestaPoint, error) {
	if len(input) != pastaImpl.FqBytes {
		return nil, errs.NewLength("invalid input")
	}

	sign := input[31] >> 7
	var buffer [pastaImpl.FqBytes]byte
	copy(buffer[:], input)
	buffer[31] &= 0x7f

	var x, y pastaImpl.Fq
	ok := x.SetBytes(buffer[:])
	if ok != 1 {
		return nil, errs.NewLength("invalid input")
	}
	if x.IsZero() == 1 && sign == 0 {
		return c.OpIdentity(), nil
	}

	pp := new(VestaPoint)
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

func (c *VestaCurve) FromAffineUncompressed(input []byte) (*VestaPoint, error) {
	if len(input) != 2*pastaImpl.FqBytes {
		return nil, errs.NewLength("invalid input")
	}

	var x, y pastaImpl.Fq
	ok := x.SetBytes(input[:pastaImpl.FqBytes])
	if ok != 1 {
		return nil, errs.NewFailed("invalid input")
	}
	ok = y.SetBytes(input[pastaImpl.FqBytes:])
	if ok != 1 {
		return nil, errs.NewFailed("invalid input")
	}
	if x.IsZero() == 1 && y.IsZero() == 1 {
		return c.OpIdentity(), nil
	}

	pp := new(VestaPoint)
	ok = pp.V.SetAffine(&x, &y)
	if ok != 1 {
		return nil, errs.NewFailed("invalid input")
	}
	return pp, nil
}

func (c *VestaCurve) NewPoint(affineX, affineY *VestaBaseFieldElement) (*VestaPoint, error) {
	//TODO implement me
	panic("implement me")
}

func (c *VestaCurve) Hash(bytes []byte) (*VestaPoint, error) {
	return c.HashWithDst(base.Hash2CurveAppTag+VestaHash2CurveSuite, bytes)
}

func (c *VestaCurve) HashWithDst(dst string, bytes []byte) (*VestaPoint, error) {
	var p VestaPoint
	p.V.Hash(dst, bytes)
	return &p, nil
}

// TODO(aalireza): doesn't make sense of curve/point
func (c *VestaCurve) ElementSize() int {
	//TODO implement me
	panic("implement me")
}

func (c *VestaCurve) WideElementSize() int {
	//TODO implement me
	panic("implement me")
}

func (c *VestaCurve) BasePoints() ds.ImmutableMap[string, *VestaPoint] {
	panic("implement me")
}

func (c *VestaCurve) ScalarField() algebra.PrimeField[*VestaScalar] {
	return NewVestaScalarField()
}

func (c *VestaCurve) BaseField() algebra.FiniteField[*VestaBaseFieldElement] {
	return NewVestaBaseField()
}

type VestaPoint struct {
	traits.Point[*pastaImpl.Fq, *pastaImpl.VestaPoint, pastaImpl.VestaPoint, *VestaPoint, VestaPoint]
}

func (p *VestaPoint) P() *pastaImpl.VestaPoint {
	return &p.V
}

func (p *VestaPoint) HashCode() uint64 {
	//TODO implement me
	panic("implement me")
}

func (p *VestaPoint) Structure() algebra.Structure[*VestaPoint] {
	return NewVestaCurve()
}

func (p *VestaPoint) MarshalBinary() (data []byte, err error) {
	//TODO implement me
	panic("implement me")
}

func (p *VestaPoint) UnmarshalBinary(data []byte) error {
	//TODO implement me
	panic("implement me")
}

// TODO(aalireza): not sure if this should always return affine coordinates or implementation defined coordinates
func (p *VestaPoint) Coordinates() []*VestaBaseFieldElement {
	var x, y FqFieldElement
	p.V.ToAffine(&x.V, &y.V)

	return []*FqFieldElement{&x, &y}
}

func (p *VestaPoint) ToAffineCompressed() []byte {
	// Use ZCash encoding where infinity is all zeros and the top bit represents the sign of y
	// and the remainder represent the x-coordinate
	if p.IsOpIdentity() {
		var zeros [pastaImpl.FqBytes]byte
		return zeros[:]
	}

	var x, y pastaImpl.Fq
	ok := p.V.ToAffine(&x, &y)
	if ok != 1 {
		panic("this should never happen")
	}
	sign := (y.Bytes()[0] & 0b1) << 7
	result := x.Bytes()
	result[31] |= sign
	return result
}

func (p *VestaPoint) ToAffineUncompressed() []byte {
	if p.IsOpIdentity() {
		var zeros [pastaImpl.FqBytes * 2]byte
		return zeros[:]
	}

	var x, y pastaImpl.Fq
	ok := p.V.ToAffine(&x, &y)
	if ok != 1 {
		panic("this should never happen")
	}

	return slices.Concat(x.Bytes(), y.Bytes())
}

func (p *VestaPoint) AffineX() (*VestaBaseFieldElement, error) {
	if p.IsZero() {
		return NewVestaBaseField().One(), nil
	}

	var x, y VestaBaseFieldElement
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		return nil, errs.NewFailed("failed to convert point to affine")
	}

	return &x, nil
}

func (p *VestaPoint) AffineY() (*VestaBaseFieldElement, error) {
	if p.IsZero() {
		return NewVestaBaseField().Zero(), nil
	}

	var x, y VestaBaseFieldElement
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		return nil, errs.NewFailed("failed to convert point to affine")
	}

	return &y, nil
}

func (p *VestaPoint) ScalarMul(actor *VestaScalar) *VestaPoint {
	var result VestaPoint
	pointsImpl.ScalarMul[*pastaImpl.Fq](&result.V, &p.V, actor.V.Bytes())
	return &result
}

func (p *VestaPoint) IsTorsionFree() bool {
	return true
}

func (p *VestaPoint) IsBasePoint(id string) bool {
	//TODO implement me
	panic("implement me")
}

// TODO(aalireza): no use of it
func (p *VestaPoint) CanBeGenerator() bool {
	//TODO implement me
	panic("implement me")
}
