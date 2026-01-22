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
	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
)

type (
	VestaBaseFieldElement = FqFieldElement
	VestaScalar           = FpFieldElement
)

const (
	// VestaName is the curve name.
	VestaName = "vesta"
	// VestaHash2CurveSuite is the hash-to-curve suite string.
	VestaHash2CurveSuite = "vesta_XMD:BLAKE2b_SSWU_RO_"
)

var (
	vestaInitOnce sync.Once
	vestaInstance *VestaCurve

	_ curves.Curve[*VestaPoint, *VestaBaseFieldElement, *VestaScalar] = (*VestaCurve)(nil)
	_ curves.Point[*VestaPoint, *VestaBaseFieldElement, *VestaScalar] = (*VestaPoint)(nil)
	_ encoding.BinaryMarshaler                                        = (*VestaPoint)(nil)
	_ encoding.BinaryUnmarshaler                                      = (*VestaPoint)(nil)
)

// VestaCurve represents the Vesta elliptic curve.
type VestaCurve struct {
	traits.PrimeCurveTrait[*pastaImpl.Fq, *pastaImpl.VestaPoint, *VestaPoint, VestaPoint]
}

// NewVestaCurve returns the Vesta curve instance.
func NewVestaCurve() *VestaCurve {
	vestaInitOnce.Do(func() {
		//nolint:exhaustruct // no need for trait
		vestaInstance = &VestaCurve{}
	})

	return vestaInstance
}

// Name returns the name of the structure.
func (*VestaCurve) Name() string {
	return VestaName
}

// Order returns the group or field order.
func (*VestaCurve) Order() cardinal.Cardinal {
	return NewVestaScalarField().Order()
}

// Cofactor returns the curve cofactor.
func (*VestaCurve) Cofactor() cardinal.Cardinal {
	return cardinal.New(1)
}

// FromBytes decodes an element from bytes.
func (c *VestaCurve) FromBytes(input []byte) (*VestaPoint, error) {
	return c.FromCompressed(input)
}

// FromCompressed decodes a compressed point.
func (c *VestaCurve) FromCompressed(input []byte) (*VestaPoint, error) {
	if len(input) != pastaImpl.FqBytes {
		return nil, curves.ErrInvalidLength.WithMessage("invalid input")
	}

	sign := input[31] >> 7
	var buffer [pastaImpl.FqBytes]byte
	copy(buffer[:], input)
	buffer[31] &= 0x7f

	var x, y pastaImpl.Fq
	ok := x.SetBytes(buffer[:])
	if ok != 1 {
		return nil, curves.ErrInvalidLength.WithMessage("invalid input")
	}
	if x.IsZero() == 1 && sign == 0 {
		return c.OpIdentity(), nil
	}

	pp := new(VestaPoint)
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
func (c *VestaCurve) FromUncompressed(input []byte) (*VestaPoint, error) {
	if len(input) != 2*pastaImpl.FqBytes {
		return nil, curves.ErrInvalidLength.WithMessage("invalid input")
	}

	var x, y pastaImpl.Fq
	ok := x.SetBytes(input[:pastaImpl.FqBytes])
	if ok != 1 {
		return nil, curves.ErrFailed.WithMessage("invalid input")
	}
	ok = y.SetBytes(input[pastaImpl.FqBytes:])
	if ok != 1 {
		return nil, curves.ErrFailed.WithMessage("invalid input")
	}
	if x.IsZero() == 1 && y.IsZero() == 1 {
		return c.OpIdentity(), nil
	}

	pp := new(VestaPoint)
	ok = pp.V.SetAffine(&x, &y)
	if ok != 1 {
		return nil, curves.ErrFailed.WithMessage("invalid input")
	}
	return pp, nil
}

// FromAffine builds a point from affine coordinates.
func (*VestaCurve) FromAffine(x, y *VestaBaseFieldElement) (*VestaPoint, error) {
	var p VestaPoint
	ok := p.V.SetAffine(&x.V, &y.V)
	if ok != 1 {
		return nil, curves.ErrInvalidCoordinates.WithMessage("x/y")
	}
	return &p, nil
}

// FromAffineX builds a point from an affine x-coordinate.
func (*VestaCurve) FromAffineX(x *VestaBaseFieldElement, b bool) (*VestaPoint, error) {
	var p VestaPoint
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
func (c *VestaCurve) Hash(bytes []byte) (*VestaPoint, error) {
	return c.HashWithDst(base.Hash2CurveAppTag+VestaHash2CurveSuite, bytes)
}

// HashWithDst maps input bytes to a point with a custom DST.
func (*VestaCurve) HashWithDst(dst string, bytes []byte) (*VestaPoint, error) {
	var p VestaPoint
	p.V.Hash(dst, bytes)
	return &p, nil
}

// ElementSize returns the element size in bytes.
func (*VestaCurve) ElementSize() int {
	return pastaImpl.FqBytes
}

// WideElementSize returns the wide element size in bytes.
func (*VestaCurve) WideElementSize() int {
	return int(^uint(0) >> 1)
}

// ScalarStructure returns the scalar structure.
func (*VestaCurve) ScalarStructure() algebra.Structure[*VestaScalar] {
	return NewVestaScalarField()
}

// BaseStructure returns the base field structure.
func (*VestaCurve) BaseStructure() algebra.Structure[*VestaBaseFieldElement] {
	return NewVestaBaseField()
}

// ScalarRing returns the scalar ring.
func (*VestaCurve) ScalarRing() algebra.ZModLike[*VestaScalar] {
	return NewVestaScalarField()
}

// ScalarField returns the scalar field.
func (*VestaCurve) ScalarField() algebra.PrimeField[*VestaScalar] {
	return NewVestaScalarField()
}

// BaseField returns the base field.
func (*VestaCurve) BaseField() algebra.FiniteField[*VestaBaseFieldElement] {
	return NewVestaBaseField()
}

// ScalarBaseOp adds a scalar multiple of the generator.
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

// ScalarBaseMul multiplies the generator by a scalar.
func (c *VestaCurve) ScalarBaseMul(sc *VestaScalar) *VestaPoint {
	if c == nil {
		return nil
	}
	if sc == nil {
		panic("scalar is nil")
	}
	return c.Generator().ScalarMul(sc)
}

// ToElliptic returns the standard library elliptic.Curve adapter.
func (*VestaCurve) ToElliptic() elliptic.Curve {
	return ellipticVestaInstance
}

// MultiScalarOp computes a multiscalar operation.
func (c *VestaCurve) MultiScalarOp(scalars []*VestaScalar, points []*VestaPoint) (*VestaPoint, error) {
	return c.MultiScalarMul(scalars, points)
}

// MultiScalarMul computes a multiscalar multiplication.
func (*VestaCurve) MultiScalarMul(scalars []*VestaScalar, points []*VestaPoint) (*VestaPoint, error) {
	if len(scalars) != len(points) {
		return nil, curves.ErrInvalidLength.WithMessage("mismatched lengths of scalars and points")
	}
	var result VestaPoint
	scs := make([][]byte, len(scalars))
	pts := make([]*pastaImpl.VestaPoint, len(points))
	for i := range points {
		pts[i] = &points[i].V
		scs[i] = scalars[i].V.Bytes()
	}
	aimpl.MultiScalarMulLowLevel(&result.V, pts, scs)
	return &result, nil
}

// VestaPoint represents a Vesta curve point.
type VestaPoint struct {
	traits.PrimePointTrait[*pastaImpl.Fq, *pastaImpl.VestaPoint, pastaImpl.VestaPoint, *VestaPoint, VestaPoint]
}

// HashCode returns a hash code for the receiver.
func (p *VestaPoint) HashCode() base.HashCode {
	h := fnv.New64a()
	_, _ = h.Write(p.ToCompressed())
	return base.HashCode(h.Sum64())
}

// Structure returns the algebraic structure for the receiver.
func (*VestaPoint) Structure() algebra.Structure[*VestaPoint] {
	return NewVestaCurve()
}

// ToCompressed encodes the point in compressed form.
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

// ToUncompressed encodes the point in uncompressed form.
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

// Bytes returns the canonical byte encoding.
func (p *VestaPoint) Bytes() []byte {
	return p.ToCompressed()
}

// AffineX returns the affine x-coordinate.
func (p *VestaPoint) AffineX() (*VestaBaseFieldElement, error) {
	if p.IsZero() {
		return nil, curves.ErrFailed.WithMessage("point is identity")
	}

	var x, y VestaBaseFieldElement
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		panic("this should never happen - failed to convert point to affine")
	}

	return &x, nil
}

// AffineY returns the affine y-coordinate.
func (p *VestaPoint) AffineY() (*VestaBaseFieldElement, error) {
	if p.IsZero() {
		return nil, curves.ErrFailed.WithMessage("point is identity")
	}

	var x, y VestaBaseFieldElement
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		panic("this should never happen - failed to convert point to affine")
	}

	return &y, nil
}

// ScalarOp adds a scalar multiple of q to the receiver.
func (p *VestaPoint) ScalarOp(sc *VestaScalar) *VestaPoint {
	return p.ScalarMul(sc)
}

// ScalarMul multiplies the point by a scalar.
func (p *VestaPoint) ScalarMul(actor *VestaScalar) *VestaPoint {
	var result VestaPoint
	aimpl.ScalarMulLowLevel(&result.V, &p.V, actor.V.Bytes())
	return &result
}

// IsTorsionFree reports whether the point is torsion-free.
func (*VestaPoint) IsTorsionFree() bool {
	return true
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (p *VestaPoint) MarshalBinary() ([]byte, error) {
	return p.ToCompressed(), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (p *VestaPoint) UnmarshalBinary(data []byte) error {
	pp, err := NewVestaCurve().FromCompressed(data)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot deserialize point")
	}
	p.V.Set(&pp.V)
	return nil
}

// String returns the string form of the receiver.
func (p *VestaPoint) String() string {
	if p.IsZero() {
		return "(0, 1, 0)"
	} else {
		return fmt.Sprintf("(%s, %s, %s)", p.V.X.String(), p.V.Y.String(), p.V.Z.String())
	}
}
