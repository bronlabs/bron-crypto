package pasta

import (
	"crypto/elliptic"
	"encoding"
	"fmt"
	"hash/fnv"
	"slices"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	aimpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	pastaImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/pasta/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
)

type (
	PallasBaseFieldElement = FpFieldElement
	PallasScalar           = FqFieldElement
)

const (
	// PallasName is the curve name.
	PallasName = "pallas"
	// PallasHash2CurveSuite is the hash-to-curve suite string.
	PallasHash2CurveSuite = "pallas_XMD:BLAKE2b_SSWU_RO_"
)

var (
	pallasInitOnce sync.Once
	pallasInstance *PallasCurve

	_ curves.Curve[*PallasPoint, *PallasBaseFieldElement, *PallasScalar] = (*PallasCurve)(nil)
	_ curves.Point[*PallasPoint, *PallasBaseFieldElement, *PallasScalar] = (*PallasPoint)(nil)
	_ encoding.BinaryMarshaler                                           = (*PallasPoint)(nil)
	_ encoding.BinaryUnmarshaler                                         = (*PallasPoint)(nil)
)

// PallasCurve represents the Pallas elliptic curve.
type PallasCurve struct {
	traits.PrimeCurveTrait[*pastaImpl.Fp, *pastaImpl.PallasPoint, *PallasPoint, PallasPoint]
}

// NewPallasCurve returns the Pallas curve instance.
func NewPallasCurve() *PallasCurve {
	pallasInitOnce.Do(func() {
		//nolint:exhaustruct // no need for trait
		pallasInstance = &PallasCurve{}
	})

	return pallasInstance
}

// Name returns the name of the structure.
func (*PallasCurve) Name() string {
	return PallasName
}

// Cofactor returns the curve cofactor.
func (*PallasCurve) Cofactor() cardinal.Cardinal {
	return cardinal.New(1)
}

// Order returns the group or field order.
func (*PallasCurve) Order() cardinal.Cardinal {
	return NewPallasScalarField().Order()
}

// FromBytes decodes an element from bytes.
func (c *PallasCurve) FromBytes(input []byte) (*PallasPoint, error) {
	return c.FromCompressed(input)
}

// FromCompressed decodes a compressed point.
func (c *PallasCurve) FromCompressed(input []byte) (*PallasPoint, error) {
	if len(input) != pastaImpl.FpBytes {
		return nil, curves.ErrInvalidLength.WithMessage("invalid input")
	}

	sign := input[pastaImpl.FpBytes-1] >> 7
	var buffer [pastaImpl.FpBytes]byte
	copy(buffer[:], input)
	buffer[pastaImpl.FpBytes-1] &= 0x7f

	var x, y pastaImpl.Fp
	ok := x.SetBytes(buffer[:])
	if ok != 1 {
		return nil, curves.ErrInvalidLength.WithMessage("invalid input")
	}
	if x.IsZero() == 1 && sign == 0 {
		return c.OpIdentity(), nil
	}

	pp := new(PallasPoint)
	ok = pp.V.SetFromAffineX(&x)
	if ok != 1 {
		return nil, curves.ErrInvalidLength.WithMessage("invalid input")
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

// FromUncompressed decodes an uncompressed point.
func (c *PallasCurve) FromUncompressed(input []byte) (*PallasPoint, error) {
	if len(input) != 2*pastaImpl.FpBytes {
		return nil, curves.ErrInvalidLength.WithMessage("invalid input")
	}

	var x, y pastaImpl.Fp
	ok := x.SetBytes(input[:pastaImpl.FpBytes])
	if ok != 1 {
		return nil, curves.ErrFailed.WithMessage("invalid input")
	}
	ok = y.SetBytes(input[pastaImpl.FpBytes:])
	if ok != 1 {
		return nil, curves.ErrFailed.WithMessage("invalid input")
	}
	if x.IsZero() == 1 && y.IsZero() == 1 {
		return c.OpIdentity(), nil
	}

	pp := new(PallasPoint)
	ok = pp.V.SetAffine(&x, &y)
	if ok != 1 {
		return nil, curves.ErrFailed.WithMessage("invalid input")
	}
	return pp, nil
}

// FromAffine builds a point from affine coordinates.
func (*PallasCurve) FromAffine(x, y *PallasBaseFieldElement) (*PallasPoint, error) {
	var p PallasPoint
	ok := p.V.SetAffine(&x.V, &y.V)
	if ok != 1 {
		return nil, curves.ErrInvalidCoordinates.WithMessage("x/y")
	}
	return &p, nil
}

// FromAffineX builds a point from an affine x-coordinate.
func (*PallasCurve) FromAffineX(x *PallasBaseFieldElement, b bool) (*PallasPoint, error) {
	var p PallasPoint
	ok := p.V.SetFromAffineX(&x.V)
	if ok != 1 {
		return nil, curves.ErrInvalidCoordinates.WithMessage("x")
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

// Hash maps input bytes to an element or point.
func (c *PallasCurve) Hash(bytes []byte) (*PallasPoint, error) {
	return c.HashWithDst(base.Hash2CurveAppTag+PallasHash2CurveSuite, bytes)
}

// HashWithDst maps input bytes to a point with a custom DST.
func (*PallasCurve) HashWithDst(dst string, bytes []byte) (*PallasPoint, error) {
	var p PallasPoint
	p.V.Hash(dst, bytes)
	return &p, nil
}

// ElementSize returns the element size in bytes.
func (*PallasCurve) ElementSize() int {
	return pastaImpl.FpBytes
}

// WideElementSize returns the wide element size in bytes.
func (*PallasCurve) WideElementSize() int {
	return int(^uint(0) >> 1)
}

// ScalarStructure returns the scalar structure.
func (*PallasCurve) ScalarStructure() algebra.Structure[*PallasScalar] {
	return NewPallasScalarField()
}

// BaseStructure returns the base field structure.
func (*PallasCurve) BaseStructure() algebra.Structure[*PallasBaseFieldElement] {
	return NewPallasBaseField()
}

// ScalarRing returns the scalar ring.
func (*PallasCurve) ScalarRing() algebra.ZModLike[*PallasScalar] {
	return NewPallasScalarField()
}

// ScalarField returns the scalar field.
func (*PallasCurve) ScalarField() algebra.PrimeField[*PallasScalar] {
	return NewPallasScalarField()
}

// BaseField returns the base field.
func (*PallasCurve) BaseField() algebra.FiniteField[*PallasBaseFieldElement] {
	return NewPallasBaseField()
}

// ScalarBaseOp adds a scalar multiple of the generator.
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

// ScalarBaseMul multiplies the generator by a scalar.
func (c *PallasCurve) ScalarBaseMul(sc *PallasScalar) *PallasPoint {
	if c == nil {
		return nil
	}
	if sc == nil {
		panic("scalar is nil")
	}
	return c.Generator().ScalarMul(sc)
}

// ToElliptic returns the standard library elliptic.Curve adapter.
func (*PallasCurve) ToElliptic() elliptic.Curve {
	return ellipticPallasInstance
}

// MultiScalarOp computes a multiscalar operation.
func (c *PallasCurve) MultiScalarOp(scalars []*PallasScalar, points []*PallasPoint) (*PallasPoint, error) {
	return c.MultiScalarMul(scalars, points)
}

// MultiScalarMul computes a multiscalar multiplication.
func (*PallasCurve) MultiScalarMul(scalars []*PallasScalar, points []*PallasPoint) (*PallasPoint, error) {
	if len(scalars) != len(points) {
		return nil, curves.ErrInvalidLength.WithMessage("mismatched lengths of scalars and points")
	}
	var result PallasPoint
	scs := make([][]byte, len(scalars))
	pts := make([]*pastaImpl.PallasPoint, len(points))
	for i := range points {
		pts[i] = &points[i].V
		scs[i] = scalars[i].V.Bytes()
	}
	aimpl.MultiScalarMulLowLevel(&result.V, pts, scs)
	return &result, nil
}

// PallasPoint represents a Pallas curve point.
type PallasPoint struct {
	traits.PrimePointTrait[*pastaImpl.Fp, *pastaImpl.PallasPoint, pastaImpl.PallasPoint, *PallasPoint, PallasPoint]
}

// HashCode returns a hash code for the receiver.
func (p *PallasPoint) HashCode() base.HashCode {
	h := fnv.New64a()
	_, _ = h.Write(p.ToCompressed())
	return base.HashCode(h.Sum64())
}

// Bytes returns the canonical byte encoding.
func (p *PallasPoint) Bytes() []byte {
	return p.ToCompressed()
}

// Structure returns the algebraic structure for the receiver.
func (*PallasPoint) Structure() algebra.Structure[*PallasPoint] {
	return NewPallasCurve()
}

// ToCompressed encodes the point in compressed form.
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

// ToUncompressed encodes the point in uncompressed form.
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

// AffineX returns the affine x-coordinate.
func (p *PallasPoint) AffineX() (*PallasBaseFieldElement, error) {
	if p.IsZero() {
		return nil, curves.ErrFailed.WithMessage("point is identity")
	}

	var x, y PallasBaseFieldElement
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		panic("this should never happen - failed to convert point to affine")
	}

	return &x, nil
}

// AffineY returns the affine y-coordinate.
func (p *PallasPoint) AffineY() (*PallasBaseFieldElement, error) {
	if p.IsZero() {
		return nil, curves.ErrFailed.WithMessage("point is identity")
	}

	var x, y PallasBaseFieldElement
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		panic("this should never happen - failed to convert point to affine")
	}

	return &y, nil
}

// ScalarOp adds a scalar multiple of q to the receiver.
func (p *PallasPoint) ScalarOp(sc *PallasScalar) *PallasPoint {
	return p.ScalarMul(sc)
}

// ScalarMul multiplies the point by a scalar.
func (p *PallasPoint) ScalarMul(actor *PallasScalar) *PallasPoint {
	var result PallasPoint
	aimpl.ScalarMulLowLevel(&result.V, &p.V, actor.V.Bytes())
	return &result
}

// IsTorsionFree reports whether the point is torsion-free.
func (*PallasPoint) IsTorsionFree() bool {
	return true
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (p *PallasPoint) MarshalBinary() ([]byte, error) {
	return p.ToCompressed(), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (p *PallasPoint) UnmarshalBinary(data []byte) error {
	pp, err := NewPallasCurve().FromCompressed(data)
	if err != nil {
		return errs2.Wrap(err).WithMessage("cannot deserialize point")
	}
	p.V.Set(&pp.V)
	return nil
}

// String returns the string form of the receiver.
func (p *PallasPoint) String() string {
	if p.IsZero() {
		return "(0, 1, 0)"
	} else {
		return fmt.Sprintf("(%s, %s, %s)", p.V.X.String(), p.V.Y.String(), p.V.Z.String())
	}
}
