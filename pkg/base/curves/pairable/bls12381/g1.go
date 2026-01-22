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
	// CurveNameG1 is the G1 curve name.
	CurveNameG1 = "BLS12381G1"
	// Hash2CurveSuiteG1 is the hash-to-curve suite string for G1.
	Hash2CurveSuiteG1 = "BLS12381G1_XMD:SHA-256_SSWU_RO_"
)

var (
	_ curves.Curve[*PointG1, *BaseFieldElementG1, *Scalar]                                                           = (*G1)(nil)
	_ curves.PairingFriendlyCurve[*PointG1, *BaseFieldElementG1, *PointG2, *BaseFieldElementG2, *GtElement, *Scalar] = (*G1)(nil)
	_ curves.Point[*PointG1, *BaseFieldElementG1, *Scalar]                                                           = (*PointG1)(nil)
	_ encoding.BinaryMarshaler                                                                                       = (*PointG1)(nil)
	_ encoding.BinaryUnmarshaler                                                                                     = (*PointG1)(nil)

	curveInstanceG1 *G1
	curveInitOnceG1 sync.Once
)

// G1 represents the BLS12-381 G1 group.
type G1 struct {
	traits.PrimeCurveTrait[*bls12381Impl.Fp, *bls12381Impl.G1Point, *PointG1, PointG1]
}

// NewG1 returns the BLS12-381 G1 group instance.
func NewG1() *G1 {
	curveInitOnceG1.Do(func() {
		//nolint:exhaustruct // no need for a trait
		curveInstanceG1 = &G1{}
	})

	return curveInstanceG1
}

// Name returns the name of the structure.
func (*G1) Name() string {
	return CurveNameG1
}

// ElementSize returns the element size in bytes.
func (*G1) ElementSize() int {
	return bls12381Impl.FpBytes
}

// WideElementSize returns the wide element size in bytes.
func (*G1) WideElementSize() int {
	return int(^uint(0) >> 1)
}

// FromWideBytes decodes an element from wide bytes.
func (c *G1) FromWideBytes(input []byte) (*PointG1, error) {
	return c.Hash(input)
}

// DualStructure returns the dual group structure.
func (*G1) DualStructure() curves.PairingFriendlyCurve[*PointG2, *BaseFieldElementG2, *PointG1, *BaseFieldElementG1, *GtElement, *Scalar] {
	return NewG2()
}

// PairingAlgorithm returns the pairing algorithm identifier.
func (*G1) PairingAlgorithm() curves.PairingAlgorithm {
	return OptimalAteAlgorithm
}

// MultiPair computes a multi-pairing.
func (*G1) MultiPair(these []*PointG1, with []*PointG2) (*GtElement, error) {
	if len(these) != len(with) {
		return nil, curves.ErrFailed.WithMessage("number of G1 and G2 points must match")
	}

	ppe := NewOptimalAtePPE()

	for i, p1 := range these {
		if err := ppe.Add(p1, with[i]); err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot add G1 and G2 points to pairing engine at index %d", i)
		}
	}
	return ppe.Result(), nil
}

// MultiPairAndInvertDuals computes a multi-pairing and inverts dual points.
func (*G1) MultiPairAndInvertDuals(these []*PointG1, with []*PointG2) (*GtElement, error) {
	if len(these) != len(with) {
		return nil, curves.ErrFailed.WithMessage("number of G1 and G2 points must match")
	}

	ppe := NewOptimalAtePPE()

	for i, p1 := range these {
		if err := ppe.AddAndInvG2(p1, with[i]); err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot add G1 and G2 points to pairing engine at index %d", i)
		}
	}
	result := ppe.Result()
	return result, nil
}

// Cofactor returns the curve cofactor.
func (*G1) Cofactor() cardinal.Cardinal {
	return cardinal.New(1)
}

// Order returns the group or field order.
func (*G1) Order() cardinal.Cardinal {
	return cardinal.NewFromNumeric(scalarFieldOrder.Nat())
}

// FromCompressed decodes a compressed point.
func (*G1) FromCompressed(input []byte) (*PointG1, error) {
	if len(input) != bls12381Impl.FpBytes {
		return nil, curves.ErrInvalidLength.WithMessage("invalid input")
	}

	var xFp, yFp, yNegFp bls12381Impl.Fp
	var xBytes [bls12381Impl.FpBytes]byte
	pp := new(PointG1)
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
		// Check that all other bytes are zero when infinity flag is set
		for i := range input {
			mask := byte(0xff)
			if i == 0 {
				mask = 0x1f // Ignore the flag bits
			}
			if input[i]&mask != 0 {
				return nil, curves.ErrFailed.WithMessage("non-zero x coordinate with infinity flag set")
			}
		}
		pp.V.SetZero()
		return pp, nil
	}

	copy(xBytes[:], input)
	// Mask away the flag bits
	xBytes[0] &= 0x1f
	slices.Reverse(xBytes[:])
	if valid := xFp.SetBytes(xBytes[:]); valid != 1 {
		return nil, curves.ErrFailed.WithMessage("invalid bytes - not in field")
	}

	if wasSquare := pp.V.SetFromAffineX(&xFp); wasSquare != 1 {
		return nil, curves.ErrFailed.WithMessage("point is not on the curve")
	}
	if ok := pp.V.ToAffine(&xFp, &yFp); ok != 1 {
		panic("this should never happen")
	}

	yNegFp.Neg(&pp.V.Y)
	pp.V.Y.Select(fieldsImpl.IsNegative(&yFp)^sortFlag, &pp.V.Y, &yNegFp)

	if !pp.IsTorsionFree() {
		return nil, curves.ErrFailed.WithMessage("point is not in correct subgroup")
	}

	return pp, nil
}

// FromAffineX builds a point from an affine x-coordinate.
func (*G1) FromAffineX(x *BaseFieldElementG1, b bool) (*PointG1, error) {
	var p PointG1
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

// FromBytes decodes an element from bytes.
func (c *G1) FromBytes(input []byte) (*PointG1, error) {
	return c.FromCompressed(input)
}

// FromUncompressed decodes an uncompressed point.
func (*G1) FromUncompressed(input []byte) (*PointG1, error) {
	if len(input) != 2*bls12381Impl.FpBytes {
		return nil, curves.ErrInvalidLength.WithMessage("invalid input")
	}

	var xFp, yFp bls12381Impl.Fp
	var t [2 * bls12381Impl.FpBytes]byte
	pp := new(PointG1)
	infinityFlag := uint64((input[0] >> 6) & 1)

	if infinityFlag == 1 {
		pp.V.SetZero()
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
		return nil, curves.ErrFailed.WithMessage("invalid bytes - x not in field")
	}
	if valid := yFp.SetBytes(yBytes); valid != 1 {
		return nil, curves.ErrFailed.WithMessage("invalid bytes - y not in field")
	}
	if valid := pp.V.SetAffine(&xFp, &yFp); valid != 1 {
		return nil, curves.ErrFailed.WithMessage("point is not on the curve")
	}
	if !pp.IsTorsionFree() {
		return nil, curves.ErrFailed.WithMessage("point is not in correct subgroup")
	}

	return pp, nil
}

// FromAffine builds a point from affine coordinates.
func (*G1) FromAffine(x, y *BaseFieldElementG1) (*PointG1, error) {
	var p PointG1
	ok := p.V.SetAffine(&x.V, &y.V)
	if ok != 1 {
		return nil, curves.ErrInvalidCoordinates.WithMessage("x/y")
	}
	return &p, nil
}

// Hash maps input bytes to an element or point.
func (c *G1) Hash(bytes []byte) (*PointG1, error) {
	return c.HashWithDst(base.Hash2CurveAppTag+Hash2CurveSuiteG1, bytes)
}

// HashWithDst maps input bytes to a point with a custom DST.
func (*G1) HashWithDst(dst string, bytes []byte) (*PointG1, error) {
	var p PointG1
	p.V.Hash(dst, bytes)
	return &p, nil
}

// ScalarStructure returns the scalar structure.
func (*G1) ScalarStructure() algebra.Structure[*Scalar] {
	return NewScalarField()
}

// BaseStructure returns the base field structure.
func (*G1) BaseStructure() algebra.Structure[*BaseFieldElementG1] {
	return NewG1BaseField()
}

// ScalarRing returns the scalar ring.
func (*G1) ScalarRing() algebra.ZModLike[*Scalar] {
	return NewScalarField()
}

// ScalarField returns the scalar field.
func (*G1) ScalarField() algebra.PrimeField[*Scalar] {
	return NewScalarField()
}

// BaseField returns the base field.
func (*G1) BaseField() algebra.FiniteField[*BaseFieldElementG1] {
	return NewG1BaseField()
}

// ScalarBaseOp adds a scalar multiple of the generator.
func (c *G1) ScalarBaseOp(sc *Scalar) *PointG1 {
	if sc.IsZero() {
		return c.OpIdentity()
	}
	return c.ScalarBaseMul(sc)
}

// ScalarBaseMul multiplies the generator by a scalar.
func (c *G1) ScalarBaseMul(sc *Scalar) *PointG1 {
	return c.Generator().ScalarMul(sc)
}

// MultiScalarOp computes a multiscalar operation.
func (c *G1) MultiScalarOp(scalars []*Scalar, points []*PointG1) (*PointG1, error) {
	return c.MultiScalarMul(scalars, points)
}

// MultiScalarMul computes a multiscalar multiplication.
func (*G1) MultiScalarMul(scalars []*Scalar, points []*PointG1) (*PointG1, error) {
	if len(scalars) != len(points) {
		return nil, curves.ErrInvalidLength.WithMessage("mismatched lengths of scalars and points")
	}
	var result PointG1
	scs := make([][]byte, len(scalars))
	pts := make([]*bls12381Impl.G1Point, len(points))
	for i := range points {
		pts[i] = &points[i].V
		scs[i] = scalars[i].V.Bytes()
	}
	aimpl.MultiScalarMulLowLevel(&result.V, pts, scs)
	return &result, nil
}

// PointG1 represents a point in G1.
type PointG1 struct {
	traits.PrimePointTrait[*bls12381Impl.Fp, *bls12381Impl.G1Point, bls12381Impl.G1Point, *PointG1, PointG1]
}

// Pair computes the pairing of p and q.
func (p *PointG1) Pair(p2 *PointG2) (*GtElement, error) {
	if p2 == nil {
		return nil, curves.ErrInvalidArgument.WithMessage("cannot pair with nil G2 point")
	}
	ppe := NewOptimalAtePPE()
	if err := ppe.Add(p, p2); err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot add G1 and G2 points to pairing engine")
	}
	return ppe.Result(), nil
}

// MultiPair computes a multi-pairing.
func (p *PointG1) MultiPair(with ...*PointG2) (*GtElement, error) {
	if len(with) == 0 {
		return nil, curves.ErrInvalidArgument.WithMessage("cannot pair with empty G2 points")
	}

	ppe := NewOptimalAtePPE()
	for _, p2 := range with {
		if err := ppe.Add(p, p2); err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot add G1 and G2 points to pairing engine")
		}
	}
	return ppe.Result(), nil
}

// MultiPairAndInvertDuals computes a multi-pairing and inverts dual points.
func (p *PointG1) MultiPairAndInvertDuals(with ...*PointG2) (*GtElement, error) {
	if len(with) == 0 {
		return nil, curves.ErrInvalidArgument.WithMessage("cannot pair with empty G2 points")
	}

	ppe := NewOptimalAtePPE()
	for _, p2 := range with {
		if err := ppe.AddAndInvG2(p, p2); err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot add G1 and G2 points to pairing engine")
		}
	}
	return ppe.Result(), nil
}

// InSourceGroup reports whether p is in the source group.
func (*PointG1) InSourceGroup() bool {
	return true
}

// HashCode returns a hash code for the receiver.
func (p *PointG1) HashCode() base.HashCode {
	h := fnv.New64a()
	_, _ = h.Write(p.ToCompressed())
	return base.HashCode(h.Sum64())
}

// Structure returns the algebraic structure for the receiver.
func (*PointG1) Structure() algebra.Structure[*PointG1] {
	return NewG1()
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (p *PointG1) MarshalBinary() (data []byte, err error) {
	return p.ToCompressed(), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (p *PointG1) UnmarshalBinary(data []byte) error {
	pp, err := NewG1().FromCompressed(data)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot deserialize point")
	}
	p.V.Set(&pp.V)
	return nil
}

// ToCompressed encodes the point in compressed form.
func (p *PointG1) ToCompressed() []byte {
	var x, y bls12381Impl.Fp
	x.SetZero()
	y.SetZero()
	p.V.ToAffine(&x, &y)

	bitC := ct.Bool(1)
	bitI := p.V.IsZero()
	bitS := fieldsImpl.IsNegative(&y) & (bitI ^ 1)
	m := byte((bitC << 7) | (bitI << 6) | (bitS << 5))

	xBytes := x.Bytes()
	slices.Reverse(xBytes)
	xBytes[0] |= m
	return xBytes
}

// ToUncompressed encodes the point in uncompressed form.
func (p *PointG1) ToUncompressed() []byte {
	var x, y bls12381Impl.Fp
	x.SetZero()
	y.SetZero()
	p.V.ToAffine(&x, &y)

	bitC := ct.Bool(0)
	bitI := p.V.IsZero()
	bitS := ct.Bool(0)
	m := byte((bitC << 7) | (bitI << 6) | (bitS << 5))

	xBytes := x.Bytes()
	slices.Reverse(xBytes)
	yBytes := y.Bytes()
	slices.Reverse(yBytes)

	result := slices.Concat(xBytes, yBytes)
	result[0] |= m
	return result
}

// AffineX returns the affine x-coordinate.
func (p *PointG1) AffineX() (*BaseFieldElementG1, error) {
	if p.IsZero() {
		return nil, curves.ErrFailed.WithMessage("point is identity")
	}

	var x, y BaseFieldElementG1
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		panic("this should never happen - failed to convert point to affine")
	}

	return &x, nil
}

// AffineY returns the affine y-coordinate.
func (p *PointG1) AffineY() (*BaseFieldElementG1, error) {
	if p.IsZero() {
		return nil, curves.ErrFailed.WithMessage("point is identity")
	}

	var x, y BaseFieldElementG1
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		panic("this should never happen - failed to convert point to affine")
	}

	return &y, nil
}

// ScalarOp adds a scalar multiple of q to the receiver.
func (p *PointG1) ScalarOp(sc *Scalar) *PointG1 {
	return p.ScalarMul(sc)
}

// ScalarMul multiplies the point by a scalar.
func (p *PointG1) ScalarMul(actor *Scalar) *PointG1 {
	var result PointG1
	aimpl.ScalarMulLowLevel(&result.V, &p.V, actor.V.Bytes())
	return &result
}

// IsTorsionFree reports whether the point is torsion-free.
func (p *PointG1) IsTorsionFree() bool {
	// Ensure scalar field is initialised
	_ = NewScalarField()
	orderBytes := scalarFieldOrder.Bytes()
	slices.Reverse(orderBytes)
	var e bls12381Impl.G1Point
	aimpl.ScalarMulLowLevel(&e, &p.V, orderBytes)
	return e.IsZero() == 1
}

// Bytes returns the canonical byte encoding.
func (p *PointG1) Bytes() []byte {
	return p.ToCompressed()
}

// String returns the string form of the receiver.
func (p *PointG1) String() string {
	if p.IsZero() {
		return "(0, 1, 0)"
	} else {
		return fmt.Sprintf("(%s, %s, %s)", p.V.X.String(), p.V.Y.String(), p.V.Z.String())
	}
}
