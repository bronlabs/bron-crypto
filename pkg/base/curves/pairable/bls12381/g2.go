package bls12381

import (
	"encoding"
	"fmt"
	"hash/fnv"
	"slices"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	aimpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	bls12381Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/errs-go/errs"
)

const (
	// CurveNameG2 is the G2 curve name.
	CurveNameG2 = "BLS12381G2"
	// Hash2CurveSuiteG2 is the hash-to-curve suite string for G2.
	Hash2CurveSuiteG2 = "BLS12381G2_XMD:SHA-256_SSWU_RO_"
)

var (
	_ curves.Curve[*PointG2, *BaseFieldElementG2, *Scalar]                                                           = (*G2)(nil)
	_ curves.PairingFriendlyCurve[*PointG2, *BaseFieldElementG2, *PointG1, *BaseFieldElementG1, *GtElement, *Scalar] = (*G2)(nil)
	_ curves.Point[*PointG2, *BaseFieldElementG2, *Scalar]                                                           = (*PointG2)(nil)
	_ encoding.BinaryMarshaler                                                                                       = (*PointG2)(nil)
	_ encoding.BinaryUnmarshaler                                                                                     = (*PointG2)(nil)

	curveInstanceG2 *G2
	curveInitOnceG2 sync.Once
)

// G2 represents the BLS12-381 G2 group.
type G2 struct {
	traits.PrimeCurveTrait[*bls12381Impl.Fp2, *bls12381Impl.G2Point, *PointG2, PointG2]
}

// NewG2 returns the BLS12-381 G2 group instance.
func NewG2() *G2 {
	curveInitOnceG2.Do(func() {
		//nolint:exhaustruct // no need for a trait
		curveInstanceG2 = &G2{}
	})

	return curveInstanceG2
}

// Name returns the name of the structure.
func (*G2) Name() string {
	return CurveNameG2
}

// ElementSize returns the element size in bytes.
func (*G2) ElementSize() int {
	return 2 * bls12381Impl.FpBytes
}

// WideElementSize returns the wide element size in bytes.
func (*G2) WideElementSize() int {
	return int(^uint(0) >> 1)
}

// FromWideBytes decodes an element from wide bytes.
func (c *G2) FromWideBytes(input []byte) (*PointG2, error) {
	return c.Hash(input)
}

// FromBytes decodes an element from bytes.
func (c *G2) FromBytes(input []byte) (*PointG2, error) {
	return c.FromCompressed(input)
}

// DualStructure returns the dual group structure.
func (*G2) DualStructure() curves.PairingFriendlyCurve[*PointG1, *BaseFieldElementG1, *PointG2, *BaseFieldElementG2, *GtElement, *Scalar] {
	return NewG1()
}

// PairingAlgorithm returns the pairing algorithm identifier.
func (*G2) PairingAlgorithm() curves.PairingAlgorithm {
	return OptimalAteAlgorithm
}

// MultiPair computes a multi-pairing.
func (*G2) MultiPair(these []*PointG2, with []*PointG1) (*GtElement, error) {
	if len(these) != len(with) {
		return nil, curves.ErrFailed.WithMessage("number of G1 and G2 points must match")
	}

	ppe := NewOptimalAtePPE()

	for i, p2 := range these {
		if err := ppe.Add(with[i], p2); err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot add G1 and G2 points to pairing engine at index %d", i)
		}
	}
	return ppe.Result(), nil
}

// MultiPairAndInvertDuals computes a multi-pairing and inverts dual points.
func (*G2) MultiPairAndInvertDuals(these []*PointG2, with []*PointG1) (*GtElement, error) {
	if len(these) != len(with) {
		return nil, curves.ErrFailed.WithMessage("number of G1 and G2 points must match")
	}

	ppe := NewOptimalAtePPE()

	for i, p2 := range these {
		if err := ppe.AddAndInvG2(with[i], p2); err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot add G1 and G2 points to pairing engine at index %d", i)
		}
	}
	result := ppe.Result()
	return result, nil
}

// Cofactor returns the curve cofactor.
func (*G2) Cofactor() cardinal.Cardinal {
	return cardinal.New(1)
}

// Order returns the group or field order.
func (*G2) Order() cardinal.Cardinal {
	return cardinal.NewFromNumeric(scalarFieldOrder.Nat())
}

// FromCompressed decodes a compressed point.
func (*G2) FromCompressed(input []byte) (*PointG2, error) {
	if len(input) != 2*bls12381Impl.FpBytes {
		return nil, curves.ErrInvalidLength.WithMessage("invalid input")
	}

	var buffer [2 * bls12381Impl.FpBytes]byte
	copy(buffer[:], input)

	result := new(PointG2)
	compressedFlag := ct.Bool((input[0] >> 7) & 1)
	infinityFlag := ct.Bool((input[0] >> 6) & 1)
	sortFlag := ct.Bool((input[0] >> 5) & 1)
	if compressedFlag != 1 {
		return nil, curves.ErrFailed.WithMessage("compressed flag must be set")
	}
	if infinityFlag == 1 {
		if sortFlag == 1 {
			return nil, curves.ErrFailed.WithMessage("infinity flag and sort flag are both set")
		}
		// Check that all other bytes are zero when an infinity flag is set
		for i := range input {
			mask := byte(0xff)
			if i == 0 {
				mask = 0x1f // Ignore the flag bits
			}
			if input[i]&mask != 0 {
				return nil, curves.ErrFailed.WithMessage("non-zero x coordinate with infinity flag set")
			}
		}
		result.V.SetZero()
		return result, nil
	}

	buffer[0] &= 0x1f
	x1Bytes := buffer[:bls12381Impl.FpBytes]
	slices.Reverse(x1Bytes)
	x0Bytes := buffer[bls12381Impl.FpBytes : 2*bls12381Impl.FpBytes]
	slices.Reverse(x0Bytes)

	var x, y, yNeg bls12381Impl.Fp2
	if ok := x.U1.SetBytes(x1Bytes); ok != 1 {
		return nil, curves.ErrFailed.WithMessage("x is not an Fp2")
	}
	if ok := x.U0.SetBytes(x0Bytes); ok != 1 {
		return nil, curves.ErrFailed.WithMessage("x is not an Fp2")
	}

	// Recover a y-coordinate given x by y = sqrt(x^3 + 4)
	pp := new(PointG2)
	if wasSquare := pp.V.SetFromAffineX(&x); wasSquare != 1 {
		return nil, curves.ErrFailed.WithMessage("point is not on the curve")
	}
	pp.V.ToAffine(&x, &y)
	yNeg.Neg(&pp.V.Y)
	pp.V.Y.Select(isNegative(&y)^sortFlag, &pp.V.Y, &yNeg)

	if !pp.IsTorsionFree() {
		return nil, curves.ErrFailed.WithMessage("point is not in correct subgroup")
	}
	return pp, nil
}

// FromUncompressed decodes an uncompressed point.
func (*G2) FromUncompressed(input []byte) (*PointG2, error) {
	if len(input) != 4*bls12381Impl.FpBytes {
		return nil, curves.ErrInvalidLength.WithMessage("invalid input")
	}

	var buffer [4 * bls12381Impl.FpBytes]byte
	copy(buffer[:], input)
	pp := new(PointG2)

	infinityFlag := uint64((input[0] >> 6) & 1)
	if infinityFlag == 1 {
		pp.V.SetZero()
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
		return nil, curves.ErrFailed.WithMessage("x is not an Fp2")
	}
	if ok := x.U0.SetBytes(x0Bytes); ok != 1 {
		return nil, curves.ErrFailed.WithMessage("x is not an Fp2")
	}
	if ok := y.U1.SetBytes(y1Bytes); ok != 1 {
		return nil, curves.ErrFailed.WithMessage("y is not an Fp2")
	}
	if ok := y.U0.SetBytes(y0Bytes); ok != 1 {
		return nil, curves.ErrFailed.WithMessage("y is not an Fp2")
	}
	if valid := pp.V.SetAffine(&x, &y); valid != 1 {
		return nil, curves.ErrFailed.WithMessage("point is not on the curve")
	}
	if !pp.IsTorsionFree() {
		return nil, curves.ErrFailed.WithMessage("point is not in correct subgroup")
	}

	return pp, nil
}

// FromAffine builds a point from affine coordinates.
func (*G2) FromAffine(x, y *BaseFieldElementG2) (*PointG2, error) {
	var p PointG2
	ok := p.V.SetAffine(&x.V, &y.V)
	if ok != 1 {
		return nil, curves.ErrInvalidCoordinates.WithMessage("x/y")
	}
	return &p, nil
}

// Hash maps input bytes to an element or point.
func (c *G2) Hash(bytes []byte) (*PointG2, error) {
	return c.HashWithDst(base.Hash2CurveAppTag+Hash2CurveSuiteG2, bytes)
}

// HashWithDst maps input bytes to a point with a custom DST.
func (*G2) HashWithDst(dst string, bytes []byte) (*PointG2, error) {
	var p PointG2
	p.V.Hash(dst, bytes)
	return &p, nil
}

// ScalarStructure returns the scalar structure.
func (*G2) ScalarStructure() algebra.Structure[*Scalar] {
	return NewScalarField()
}

// BaseStructure returns the base field structure.
func (*G2) BaseStructure() algebra.Structure[*BaseFieldElementG2] {
	return NewG2BaseField()
}

// ScalarRing returns the scalar ring.
func (*G2) ScalarRing() algebra.ZModLike[*Scalar] {
	return NewScalarField()
}

// ScalarField returns the scalar field.
func (*G2) ScalarField() algebra.PrimeField[*Scalar] {
	return NewScalarField()
}

// BaseField returns the base field.
func (*G2) BaseField() algebra.FiniteField[*BaseFieldElementG2] {
	return NewG2BaseField()
}

// ScalarBaseOp adds a scalar multiple of the generator.
func (c *G2) ScalarBaseOp(sc *Scalar) *PointG2 {
	if sc.IsZero() {
		return c.OpIdentity()
	}
	return c.ScalarBaseMul(sc)
}

// ScalarBaseMul multiplies the generator by a scalar.
func (c *G2) ScalarBaseMul(sc *Scalar) *PointG2 {
	return c.Generator().ScalarMul(sc)
}

// MultiScalarOp computes a multiscalar operation.
func (c *G2) MultiScalarOp(scalars []*Scalar, points []*PointG2) (*PointG2, error) {
	return c.MultiScalarMul(scalars, points)
}

// MultiScalarMul computes a multiscalar multiplication.
func (*G2) MultiScalarMul(scalars []*Scalar, points []*PointG2) (*PointG2, error) {
	if len(scalars) != len(points) {
		return nil, curves.ErrInvalidLength.WithMessage("mismatched lengths of scalars and points")
	}
	var result PointG2
	scs := make([][]byte, len(scalars))
	pts := make([]*bls12381Impl.G2Point, len(points))
	for i := range points {
		pts[i] = &points[i].V
		scs[i] = scalars[i].V.Bytes()
	}
	aimpl.MultiScalarMulLowLevel(&result.V, pts, scs)
	return &result, nil
}

// PointG2 represents a point in G2.
type PointG2 struct {
	traits.PrimePointTrait[*bls12381Impl.Fp2, *bls12381Impl.G2Point, bls12381Impl.G2Point, *PointG2, PointG2]
}

// InSourceGroup reports whether p is in the source group.
func (*PointG2) InSourceGroup() bool {
	return false
}

// Pair computes the pairing of p and q.
func (p *PointG2) Pair(p1 *PointG1) (*GtElement, error) {
	if p1 == nil {
		return nil, curves.ErrInvalidArgument.WithMessage("cannot pair with nil G2 point")
	}
	ppe := NewOptimalAtePPE()
	if err := ppe.Add(p1, p); err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot add G1 and G2 points to pairing engine")
	}
	return ppe.Result(), nil
}

// MultiPair computes a multi-pairing.
func (p *PointG2) MultiPair(with ...*PointG1) (*GtElement, error) {
	if len(with) == 0 {
		return nil, curves.ErrInvalidArgument.WithMessage("cannot pair with empty G2 points")
	}

	ppe := NewOptimalAtePPE()
	for _, p1 := range with {
		if err := ppe.Add(p1, p); err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot add G1 and G2 points to pairing engine")
		}
	}
	return ppe.Result(), nil
}

// MultiPairAndInvertDuals computes a multi-pairing and inverts dual points.
func (p *PointG2) MultiPairAndInvertDuals(with ...*PointG1) (*GtElement, error) {
	if len(with) == 0 {
		return nil, curves.ErrInvalidArgument.WithMessage("cannot pair with empty G2 points")
	}

	ppe := NewOptimalAtePPE()
	for _, p1 := range with {
		if err := ppe.AddAndInvG2(p1, p); err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot add G1 and G2 points to pairing engine")
		}
	}
	return ppe.Result(), nil
}

// HashCode returns a hash code for the receiver.
func (p *PointG2) HashCode() base.HashCode {
	h := fnv.New64a()
	_, _ = h.Write(p.ToCompressed())
	return base.HashCode(h.Sum64())
}

// Structure returns the algebraic structure for the receiver.
func (*PointG2) Structure() algebra.Structure[*PointG2] {
	return NewG2()
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (p *PointG2) MarshalBinary() (data []byte, err error) {
	return p.ToCompressed(), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (p *PointG2) UnmarshalBinary(data []byte) error {
	pp, err := NewG2().FromCompressed(data)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot deserialize point")
	}
	p.V.Set(&pp.V)
	return nil
}

// ToCompressed encodes the point in compressed form.
func (p *PointG2) ToCompressed() []byte {
	var x, y bls12381Impl.Fp2
	x.SetZero()
	y.SetZero()
	p.V.ToAffine(&x, &y)
	isInfinity := p.V.IsZero()

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

// ToUncompressed encodes the point in uncompressed form.
func (p *PointG2) ToUncompressed() []byte {
	var x, y bls12381Impl.Fp2
	x.SetZero()
	y.SetZero()
	isInfinity := p.V.IsZero()
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

// AffineX returns the affine x-coordinate.
func (p *PointG2) AffineX() (*BaseFieldElementG2, error) {
	if p.IsZero() {
		return nil, curves.ErrFailed.WithMessage("point is at infinity")
	}

	var x, y BaseFieldElementG2
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		panic("this should never happen - failed to convert point to affine")
	}

	return &x, nil
}

// AffineY returns the affine y-coordinate.
func (p *PointG2) AffineY() (*BaseFieldElementG2, error) {
	if p.IsZero() {
		return nil, curves.ErrFailed.WithMessage("point is at infinity")
	}

	var x, y BaseFieldElementG2
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		panic("this should never happen - failed to convert point to affine")
	}

	return &y, nil
}

// ScalarOp adds a scalar multiple of q to the receiver.
func (p *PointG2) ScalarOp(sc *Scalar) *PointG2 {
	return p.ScalarMul(sc)
}

// ScalarMul multiplies the point by a scalar.
func (p *PointG2) ScalarMul(actor *Scalar) *PointG2 {
	var result PointG2
	aimpl.ScalarMulLowLevel(&result.V, &p.V, actor.V.Bytes())
	return &result
}

// IsTorsionFree reports whether the point is torsion-free.
func (p *PointG2) IsTorsionFree() bool {
	// Ensure scalar field is initialised
	_ = NewScalarField()
	orderBytes := scalarFieldOrder.Bytes()
	slices.Reverse(orderBytes)
	var e bls12381Impl.G2Point
	aimpl.ScalarMulLowLevel(&e, &p.V, orderBytes)
	return e.IsZero() == 1
}

func isNegative(v *bls12381Impl.Fp2) ct.Bool {
	c1Neg := fieldsImpl.IsNegative(&v.U1)
	c0Neg := fieldsImpl.IsNegative(&v.U0)
	c1Zero := v.U1.IsZero()

	return c1Neg | (c1Zero & c0Neg)
}

// Bytes returns the canonical byte encoding.
func (p *PointG2) Bytes() []byte {
	return p.ToCompressed()
}

// String returns the string form of the receiver.
func (p *PointG2) String() string {
	if p.IsZero() {
		return "(0x + 0, 0x + 1, 0x + 0)"
	} else {
		return fmt.Sprintf("(%sx + %s, %sx + %s, %sx + %s)", p.V.X.U1.String(), p.V.X.U0.String(), p.V.Y.U1.String(), p.V.Y.U0.String(), p.V.Z.U1.String(), p.V.Z.U0.String())
	}
}
