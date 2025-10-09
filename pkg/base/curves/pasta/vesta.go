package pasta

import (
	"hash/fnv"
	"slices"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	aimpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	pastaImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/pasta/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
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

	_ curves.Curve[*VestaPoint, *VestaBaseFieldElement, *VestaScalar] = (*VestaCurve)(nil)
	_ curves.Point[*VestaPoint, *VestaBaseFieldElement, *VestaScalar] = (*VestaPoint)(nil)
)

type VestaCurve struct {
	traits.PrimeCurveTrait[*pastaImpl.Fq, *pastaImpl.VestaPoint, *VestaPoint, VestaPoint]
	traits.MSMTrait[*VestaScalar, *VestaPoint]
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


func (c *VestaCurve) Order() cardinal.Cardinal {
	return cardinal.NewFromSaferith(fpFieldOrder.Nat())
}

func (c *VestaCurve) Cofactor() cardinal.Cardinal {
	return cardinal.New(1)
}

func (c *VestaCurve) FromBytes(input []byte) (*VestaPoint, error) {
	return c.FromCompressed(input)
}

func (c *VestaCurve) FromCompressed(input []byte) (*VestaPoint, error) {
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

func (c *VestaCurve) FromUncompressed(input []byte) (*VestaPoint, error) {
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

func (c *VestaCurve) Hash(bytes []byte) (*VestaPoint, error) {
	return c.HashWithDst(base.Hash2CurveAppTag+VestaHash2CurveSuite, bytes)
}

func (c *VestaCurve) HashWithDst(dst string, bytes []byte) (*VestaPoint, error) {
	var p VestaPoint
	p.V.Hash(dst, bytes)
	return &p, nil
}

func (c *VestaCurve) ElementSize() int {
	return pastaImpl.FqBytes
}

func (c *VestaCurve) WideElementSize() int {
	return int(^uint(0) >> 1)
}

func (c *VestaCurve) ScalarStructure() algebra.Structure[*VestaScalar] {
	return NewVestaScalarField()
}

func (c *VestaCurve) BaseStructure() algebra.Structure[*VestaBaseFieldElement] {
	return NewVestaBaseField()
}

func (c *VestaCurve) ScalarBaseOp(sc *VestaScalar) *VestaPoint {
	if c == nil {
		return nil
	}
	if sc == nil {
		panic("scalar is nil")
	}
	if sc.IsZero() {
		return c.OpIdentity()
	}
	return c.ScalarBaseMul(sc)
}

func (c *VestaCurve) ScalarBaseMul(sc *VestaScalar) *VestaPoint {
	if c == nil {
		return nil
	}
	if sc == nil {
		panic("scalar is nil")
	}
	return c.Generator().ScalarMul(sc)
}

type VestaPoint struct {
	traits.PrimePointTrait[*pastaImpl.Fq, *pastaImpl.VestaPoint, pastaImpl.VestaPoint, *VestaPoint, VestaPoint]
}

func (p *VestaPoint) HashCode() base.HashCode {
	h := fnv.New64a()
	_, _ = h.Write(p.ToCompressed())
	return base.HashCode(h.Sum64())
}

func (p *VestaPoint) Structure() algebra.Structure[*VestaPoint] {
	return NewVestaCurve()
}

func (p *VestaPoint) Coordinates() algebra.Coordinates[*VestaBaseFieldElement] {
	var x, y VestaBaseFieldElement
	p.V.ToAffine(&x.V, &y.V)

	return algebra.NewCoordinates(
		algebra.AffineCoordinateSystem,
		&x, &y,
	)
}

func (p *VestaPoint) ToCompressed() []byte {
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

func (p *VestaPoint) ToUncompressed() []byte {
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

func (p *VestaPoint) Bytes() []byte {
	return p.ToCompressed()
}

func (p *VestaPoint) AffineX() *VestaBaseFieldElement {
	if p.IsZero() {
		return NewVestaBaseField().One()
	}

	var x, y VestaBaseFieldElement
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		panic("this should never happen - failed to convert point to affine")
	}

	return &x
}

func (p *VestaPoint) AffineY() *VestaBaseFieldElement {
	if p.IsZero() {
		return NewVestaBaseField().Zero()
	}

	var x, y VestaBaseFieldElement
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		panic("this should never happen - failed to convert point to affine")
	}

	return &y
}

func (p *VestaPoint) ScalarOp(sc *VestaScalar) *VestaPoint {
	return p.ScalarMul(sc)
}

func (p *VestaPoint) ScalarMul(actor *VestaScalar) *VestaPoint {
	var result VestaPoint
	aimpl.ScalarMul(&result.V, &p.V, actor.V.Bytes())
	return &result
}

func (p *VestaPoint) IsTorsionFree() bool {
	return true
}

func (p *VestaPoint) String() string {
	return traits.StringifyPoint(p)
}
