package pasta

import (
	"crypto/elliptic"
	"fmt"
	"hash/fnv"
	"slices"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	aimpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/universal"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	pastaImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/pasta/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
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

	pallasModelInstance *universal.ThreeSortedModel[*PallasPoint, *PallasScalar, *PallasBaseFieldElement]
	pallasModelInitOnce sync.Once

	_ curves.Curve[*PallasPoint, *PallasBaseFieldElement, *PallasScalar] = (*PallasCurve)(nil)
	_ curves.Point[*PallasPoint, *PallasBaseFieldElement, *PallasScalar] = (*PallasPoint)(nil)
)

type PallasCurve struct {
	traits.PrimeCurveTrait[*pastaImpl.Fp, *pastaImpl.PallasPoint, *PallasPoint, PallasPoint]
	traits.MSMTrait[*PallasScalar, *PallasPoint]
}

func NewPallasCurve() *PallasCurve {
	pallasInitOnce.Do(func() {
		pallasInstance = &PallasCurve{}
	})

	return pallasInstance
}

func NewPallasModel() *universal.ThreeSortedModel[*PallasPoint, *PallasScalar, *PallasBaseFieldElement] {
	pallasModelInitOnce.Do(func() {
		var err error
		pallasModelInstance, err = impl.CurveModel(
			NewPallasCurve(), NewPallasBaseField(), NewPallasScalarField(),
		)
		if err != nil {
			panic(err)
		}
	})

	return pallasModelInstance
}

func (c *PallasCurve) Name() string {
	return PallasName
}

func (c *PallasCurve) Model() *universal.Model[*PallasPoint] {
	return NewPallasModel().First()
}

func (c *PallasCurve) Cofactor() cardinal.Cardinal {
	return cardinal.New(1)
}

func (c *PallasCurve) Order() cardinal.Cardinal {
	return cardinal.NewFromNat(fqFieldOrder.Nat())
}

func (c *PallasCurve) FromBytes(input []byte) (*PallasPoint, error) {
	return c.FromCompressed(input)
}

func (c *PallasCurve) FromCompressed(input []byte) (*PallasPoint, error) {
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

func (c *PallasCurve) FromUncompressed(input []byte) (*PallasPoint, error) {
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

func (c *PallasCurve) FromAffine(x, y *PallasBaseFieldElement) (*PallasPoint, error) {
	var p PallasPoint
	ok := p.V.SetAffine(&x.V, &y.V)
	if ok != 1 {
		return nil, errs.NewCoordinates("x/y")
	}
	return &p, nil
}

func (c *PallasCurve) FromAffineX(x *PallasBaseFieldElement, b bool) (*PallasPoint, error) {
	var p PallasPoint
	ok := p.V.SetFromAffineX(&x.V)
	if ok != 1 {
		return nil, errs.NewCoordinates("x")
	}
	y, err := p.AffineY()
	if err != nil {
		panic(err) // should never happen
	}
	if y.IsOdd() != b {
		return p.Neg(), nil
	} else {
		return &p, nil
	}
}

func (c *PallasCurve) Hash(bytes []byte) (*PallasPoint, error) {
	return c.HashWithDst(base.Hash2CurveAppTag+PallasHash2CurveSuite, bytes)
}

func (c *PallasCurve) HashWithDst(dst string, bytes []byte) (*PallasPoint, error) {
	var p PallasPoint
	p.V.Hash(dst, bytes)
	return &p, nil
}

func (c *PallasCurve) ElementSize() int {
	return pastaImpl.FpBytes
}

func (c *PallasCurve) WideElementSize() int {
	return int(^uint(0) >> 1)
}

func (c *PallasCurve) ScalarStructure() algebra.Structure[*PallasScalar] {
	return NewPallasScalarField()
}

func (c *PallasCurve) BaseStructure() algebra.Structure[*PallasBaseFieldElement] {
	return NewPallasBaseField()
}

func (c *PallasCurve) ScalarBaseOp(sc *PallasScalar) *PallasPoint {
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

func (c *PallasCurve) ScalarBaseMul(sc *PallasScalar) *PallasPoint {
	if c == nil {
		return nil
	}
	if sc == nil {
		panic("scalar is nil")
	}
	return c.Generator().ScalarMul(sc)
}

func (c *PallasCurve) ToElliptic() elliptic.Curve {
	return ellipticPallasInstance
}

type PallasPoint struct {
	traits.PrimePointTrait[*pastaImpl.Fp, *pastaImpl.PallasPoint, pastaImpl.PallasPoint, *PallasPoint, PallasPoint]
}

func (p *PallasPoint) HashCode() base.HashCode {
	h := fnv.New64a()
	_, _ = h.Write(p.ToCompressed())
	return base.HashCode(h.Sum64())
}

func (p *PallasPoint) Bytes() []byte {
	return p.ToCompressed()
}

func (p *PallasPoint) Structure() algebra.Structure[*PallasPoint] {
	return NewPallasCurve()
}

func (p *PallasPoint) Coordinates() algebra.Coordinates[*PallasBaseFieldElement] {
	var x, y PallasBaseFieldElement
	p.V.ToAffine(&x.V, &y.V)

	return algebra.NewCoordinates(
		algebra.AffineCoordinateSystem,
		&x, &y,
	)
}

func (p *PallasPoint) ToCompressed() []byte {
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

func (p *PallasPoint) ToUncompressed() []byte {
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
		return nil, errs.NewFailed("point is identity")
	}

	var x, y PallasBaseFieldElement
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		panic("this should never happen - failed to convert point to affine")
	}

	return &x, nil
}

func (p *PallasPoint) AffineY() (*PallasBaseFieldElement, error) {
	if p.IsZero() {
		return nil, errs.NewFailed("point is identity")
	}

	var x, y PallasBaseFieldElement
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		panic("this should never happen - failed to convert point to affine")
	}

	return &y, nil
}

func (p *PallasPoint) ScalarOp(sc *PallasScalar) *PallasPoint {
	return p.ScalarMul(sc)
}

func (p *PallasPoint) ScalarMul(actor *PallasScalar) *PallasPoint {
	var result PallasPoint
	aimpl.ScalarMul(&result.V, &p.V, actor.V.Bytes())
	return &result
}

func (p *PallasPoint) IsTorsionFree() bool {
	return true
}

func (p *PallasPoint) String() string {
	if p.IsZero() {
		return "(0, 1, 0)"
	} else {
		return fmt.Sprintf("(%s, %s, %s)", p.V.X.String(), p.V.Y.String(), p.V.Z.String())
	}
}
