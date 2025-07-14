package edwards25519

import (
	"fmt"
	"hash/fnv"
	"slices"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	edwards25519Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519/impl"
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
)

var (
	PrimeCurveName = fmt.Sprintf("%s(PrimeSubGroup)", CurveName)

	_ curves.Curve[*PrimeSubGroupPoint, *BaseFieldElement, *Scalar] = (*PrimeSubGroup)(nil)
	_ curves.Point[*PrimeSubGroupPoint, *BaseFieldElement, *Scalar] = (*PrimeSubGroupPoint)(nil)

	primeSubGroupInstance *PrimeSubGroup
	primeSubGroupInitOnce sync.Once
)

func NewPrimeSubGroup() *PrimeSubGroup {
	primeSubGroupInitOnce.Do(func() {
		primeSubGroupInstance = &PrimeSubGroup{}
	})

	return primeSubGroupInstance
}

type PrimeSubGroup struct {
	traits.PrimeCurveTrait[*edwards25519Impl.Fp, *edwards25519Impl.Point, *PrimeSubGroupPoint, PrimeSubGroupPoint]
	traits.MSMTrait[*Scalar, *PrimeSubGroupPoint]
}

func (c *PrimeSubGroup) Name() string {
	return PrimeCurveName
}

func (c *PrimeSubGroup) ElementSize() int {
	return compressedPointBytes
}
func (c *PrimeSubGroup) WideElementSize() int {
	return int(^uint(0) >> 1)
}

func (c *PrimeSubGroup) FromWideBytes(input []byte) (*PrimeSubGroupPoint, error) {
	return c.Hash(input)
}

func (c *PrimeSubGroup) Cofactor() cardinal.Cardinal {
	return cardinal.New(8)
}

func (c *PrimeSubGroup) Order() cardinal.Cardinal {
	return cardinal.NewFromNat(scalarFieldOrder.Nat())
}

func (c *PrimeSubGroup) FromCompressed(inBytes []byte) (*PrimeSubGroupPoint, error) {
	if len(inBytes) != compressedPointBytes {
		return nil, errs.NewLength("input must be 32 bytes long")
	}

	var yBytes [32]byte
	copy(yBytes[:], inBytes)
	var y BaseFieldElement
	yBytes[31] &= 0x7f
	ok := y.V.SetBytes(yBytes[:])
	if ok != 1 {
		return nil, errs.NewFailed("invalid point")
	}

	var x BaseFieldElement
	result := new(PrimeSubGroupPoint)
	ok = result.V.SetFromAffineY(&y.V)
	_ = result.V.ToAffine(&x.V, &y.V)
	if ok != 1 {
		return nil, errs.NewFailed("invalid point")
	}

	isOdd := uint64(inBytes[31] >> 7)
	if fieldsImpl.IsOdd(&x.V) != isOdd {
		result = result.Neg()
	}
	if !result.IsTorsionFree() {
		return nil, errs.NewFailed("point is not in the prime subgroup")
	}
	return result, nil
}

func (c *PrimeSubGroup) FromBytes(inBytes []byte) (*PrimeSubGroupPoint, error) {
	return c.FromCompressed(inBytes)
}

func (c *PrimeSubGroup) FromUncompressed(inBytes []byte) (*PrimeSubGroupPoint, error) {
	if len(inBytes) != 2*32 {
		return nil, errs.NewLength("invalid byte sequence")
	}
	yBytes := inBytes[:32]
	xBytes := inBytes[32:]

	var x, y BaseFieldElement
	ok := x.V.SetBytes(xBytes)
	if ok != 1 {
		return nil, errs.NewCoordinates("x")
	}
	ok = y.V.SetBytes(yBytes)
	if ok != 1 {
		return nil, errs.NewCoordinates("y")
	}

	result := new(PrimeSubGroupPoint)
	ok = result.V.SetAffine(&x.V, &y.V)
	if ok != 1 {
		return nil, errs.NewCoordinates("x/y")
	}
	if !result.IsTorsionFree() {
		return nil, errs.NewFailed("point is not in the prime subgroup")
	}
	return result, nil
}

func (c *PrimeSubGroup) Hash(bytes []byte) (*PrimeSubGroupPoint, error) {
	return c.HashWithDst(base.Hash2CurveAppTag+Hash2CurveSuite, bytes)
}

func (c *PrimeSubGroup) HashWithDst(dst string, bytes []byte) (*PrimeSubGroupPoint, error) {
	var p PrimeSubGroupPoint
	p.V.Hash(dst, bytes)
	return &p, nil
}

func (c *PrimeSubGroup) ScalarStructure() algebra.Structure[*Scalar] {
	return NewScalarField()
}

func (c *PrimeSubGroup) BaseStructure() algebra.Structure[*BaseFieldElement] {
	return NewBaseField()
}

func (c *PrimeSubGroup) ScalarBaseOp(sc *Scalar) *PrimeSubGroupPoint {
	if sc.IsZero() {
		return c.OpIdentity()
	}
	return c.ScalarBaseMul(sc)
}

func (c *PrimeSubGroup) ScalarBaseMul(sc *Scalar) *PrimeSubGroupPoint {
	return c.Generator().ScalarMul(sc)
}

type PrimeSubGroupPoint struct {
	traits.PrimePointTrait[*edwards25519Impl.Fp, *edwards25519Impl.Point, edwards25519Impl.Point, *PrimeSubGroupPoint, PrimeSubGroupPoint]
}

func (p *PrimeSubGroupPoint) HashCode() base.HashCode {
	h := fnv.New64a()
	_, _ = h.Write(p.ToCompressed())
	return base.HashCode(h.Sum64())
}

func (p *PrimeSubGroupPoint) Structure() algebra.Structure[*PrimeSubGroupPoint] {
	return NewPrimeSubGroup()
}

func (p *PrimeSubGroupPoint) MarshalBinary() (data []byte, err error) {
	return p.ToCompressed(), nil
}

func (p *PrimeSubGroupPoint) UnmarshalBinary(data []byte) error {
	pp, err := NewCurve().FromCompressed(data)
	if err != nil {
		return errs.WrapSerialisation(err, "cannot deserialize point")
	}

	p.V.Set(&pp.V)
	return nil
}

func (p PrimeSubGroupPoint) Coordinates() algebra.Coordinates[*BaseFieldElement] {
	var x, y BaseFieldElement
	p.V.ToAffine(&x.V, &y.V)

	return algebra.Coordinates[*BaseFieldElement]{
		Value: []*BaseFieldElement{&x, &y},
		Name:  algebra.AffineCoordinateSystem,
	}
}

func (p *PrimeSubGroupPoint) ToCompressed() []byte {
	var x, y BaseFieldElement
	_ = p.V.ToAffine(&x.V, &y.V)
	yBytes := y.V.Bytes()
	yBytes[31] |= byte(fieldsImpl.IsOdd(&x.V) << 7)
	return yBytes
}

func (p *PrimeSubGroupPoint) ToUncompressed() []byte {
	var x, y BaseFieldElement
	_ = p.V.ToAffine(&x.V, &y.V)

	return slices.Concat(y.V.Bytes(), x.V.Bytes())
}

func (p *PrimeSubGroupPoint) AffineX() *BaseFieldElement {
	if p.IsZero() {
		return NewBaseField().Zero()
	}
	var x, y BaseFieldElement
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		panic("this should never happen - failed to convert point to affine")
	}

	return &x
}

func (p *PrimeSubGroupPoint) AffineY() *BaseFieldElement {
	if p.IsZero() {
		return NewBaseField().One()
	}

	var x, y BaseFieldElement
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		panic("this should never happen - failed to convert point to affine")
	}

	return &y
}

func (p *PrimeSubGroupPoint) ScalarOp(sc *Scalar) *PrimeSubGroupPoint {
	return p.ScalarMul(sc)
}

func (p *PrimeSubGroupPoint) ScalarMul(actor *Scalar) *PrimeSubGroupPoint {
	var result PrimeSubGroupPoint
	pointsImpl.ScalarMul[*edwards25519Impl.Fp](&result.V, &p.V, actor.V.Bytes())
	return &result
}

func (p *PrimeSubGroupPoint) IsTorsionFree() bool {
	primeOrderBytes := scalarFieldOrder.Bytes()
	slices.Reverse(primeOrderBytes)
	var e edwards25519Impl.Point
	pointsImpl.ScalarMul[*edwards25519Impl.Fp](&e, &p.V, primeOrderBytes)
	return e.IsIdentity() == 1
}

func (p *PrimeSubGroupPoint) Bytes() []byte {
	return p.ToCompressed()
}

func (p *PrimeSubGroupPoint) String() string {
	return traits.StringifyPoint(p)
}
