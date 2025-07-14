package bls12381

import (
	"hash/fnv"
	"slices"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/ase/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	bls12381Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

const (
	CurveNameG2       = "BLS12381G2"
	Hash2CurveSuiteG2 = "BLS12381G2_XMD:SHA-256_SSWU_RO_"
)

var (
	_ curves.Curve[*PointG2, *BaseFieldElementG2, *Scalar]                                                           = (*G2)(nil)
	_ curves.PairingFriendlyCurve[*PointG2, *BaseFieldElementG2, *PointG1, *BaseFieldElementG1, *GtElement, *Scalar] = (*G2)(nil)
	_ curves.Point[*PointG2, *BaseFieldElementG2, *Scalar]                                                           = (*PointG2)(nil)

	curveInstanceG2 *G2
	curveInitOnceG2 sync.Once
)

type G2 struct {
	traits.PrimeCurveTrait[*bls12381Impl.Fp2, *bls12381Impl.G2Point, *PointG2, PointG2]
	traits.MSMTrait[*Scalar, *PointG2]
}

func NewG2() *G2 {
	curveInitOnceG2.Do(func() {
		curveInstanceG2 = &G2{}
	})

	return curveInstanceG2
}

func (c *G2) Name() string {
	return CurveNameG2
}

func (c *G2) ElementSize() int {
	return 2 * bls12381Impl.FpBytes
}
func (c *G2) WideElementSize() int {
	return int(^uint(0) >> 1)
}
func (c *G2) FromWideBytes(input []byte) (*PointG2, error) {
	return c.Hash(input)
}

func (c *G2) FromBytes(input []byte) (*PointG2, error) {
	return c.FromCompressed(input)
}

func (c *G2) DualStructure() curves.PairingFriendlyCurve[*PointG1, *BaseFieldElementG1, *PointG2, *BaseFieldElementG2, *GtElement, *Scalar] {
	return NewG1()
}

func (c *G2) PairingAlgorithm() curves.PairingAlgorithm {
	return OptimalAteAlgorithm
}

func (c *G2) MultiPair(these []*PointG2, with []*PointG1) (*GtElement, error) {
	if len(these) != len(with) {
		return nil, errs.NewFailed("number of G1 and G2 points must match")
	}

	ppe := NewOptimalAtePPE()

	for i, p2 := range these {
		if err := ppe.Add(with[i], p2); err != nil {
			return nil, errs.WrapFailed(err, "cannot add G1 and G2 points to pairing engine at index %d", i)
		}
	}
	return ppe.Result(), nil
}

func (c *G2) MultiPairAndInvertDuals(these []*PointG2, with []*PointG1) (*GtElement, error) {
	if len(these) != len(with) {
		return nil, errs.NewFailed("number of G1 and G2 points must match")
	}

	ppe := NewOptimalAtePPE()

	for i, p2 := range these {
		if err := ppe.AddAndInvG2(with[i], p2); err != nil {
			return nil, errs.WrapFailed(err, "cannot add G1 and G2 points to pairing engine at index %d", i)
		}
	}
	result := ppe.Result()
	return result, nil
}

func (c *G2) Cofactor() cardinal.Cardinal {
	return cardinal.New(1)
}

func (c *G2) Order() cardinal.Cardinal {
	return cardinal.NewFromNat(scalarFieldOrder.Nat())
}

func (c *G2) FromCompressed(input []byte) (*PointG2, error) {
	if len(input) != 2*bls12381Impl.FpBytes {
		return nil, errs.NewLength("invalid input")
	}

	var buffer [2 * bls12381Impl.FpBytes]byte
	copy(buffer[:], input)

	result := new(PointG2)
	compressedFlag := uint64((buffer[0] >> 7) & 1)
	infinityFlag := uint64((buffer[0] >> 6) & 1)
	sortFlag := uint64((buffer[0] >> 5) & 1)
	if compressedFlag != 1 {
		return nil, errs.NewFailed("compressed flag must be set")
	}
	if infinityFlag == 1 {
		if sortFlag == 1 {
			return nil, errs.NewFailed("infinity flag and sort flag are both set")
		}
		// Check that all other bytes are zero when infinity flag is set
		for i := 0; i < len(input); i++ {
			mask := byte(0xff)
			if i == 0 {
				mask = 0x1f // Ignore the flag bits
			}
			if input[i]&mask != 0 {
				return nil, errs.NewFailed("non-zero x coordinate with infinity flag set")
			}
		}
		result.V.SetIdentity()
		return result, nil
	}

	buffer[0] &= 0x1f
	x1Bytes := buffer[:bls12381Impl.FpBytes]
	slices.Reverse(x1Bytes)
	x0Bytes := buffer[bls12381Impl.FpBytes : 2*bls12381Impl.FpBytes]
	slices.Reverse(x0Bytes)

	var x, y, yNeg bls12381Impl.Fp2
	if ok := x.U1.SetBytes(x1Bytes); ok != 1 {
		return nil, errs.NewFailed("x is not an Fp2")
	}
	if ok := x.U0.SetBytes(x0Bytes); ok != 1 {
		return nil, errs.NewFailed("x is not an Fp2")
	}

	// Recover a y-coordinate given x by y = sqrt(x^3 + 4)
	pp := new(PointG2)
	if wasSquare := pp.V.SetFromAffineX(&x); wasSquare != 1 {
		return nil, errs.NewFailed("point is not on the curve")
	}
	pp.V.ToAffine(&x, &y)
	yNeg.Neg(&pp.V.Y)
	pp.V.Y.Select(isNegative(&y)^sortFlag, &pp.V.Y, &yNeg)

	if !pp.IsTorsionFree() {
		return nil, errs.NewFailed("point is not in correct subgroup")
	}
	return pp, nil
}

func (c *G2) FromUncompressed(input []byte) (*PointG2, error) {
	if len(input) != 4*bls12381Impl.FpBytes {
		return nil, errs.NewLength("invalid input")
	}

	var buffer [4 * bls12381Impl.FpBytes]byte
	copy(buffer[:], input)
	pp := new(PointG2)

	infinityFlag := uint64((input[0] >> 6) & 1)
	if infinityFlag == 1 {
		pp.V.SetIdentity()
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
		return nil, errs.NewFailed("x is not an Fp2")
	}
	if ok := x.U0.SetBytes(x0Bytes); ok != 1 {
		return nil, errs.NewFailed("x is not an Fp2")
	}
	if ok := y.U1.SetBytes(y1Bytes); ok != 1 {
		return nil, errs.NewFailed("y is not an Fp2")
	}
	if ok := y.U0.SetBytes(y0Bytes); ok != 1 {
		return nil, errs.NewFailed("y is not an Fp2")
	}
	if valid := pp.V.SetAffine(&x, &y); valid != 1 {
		return nil, errs.NewFailed("point is not on the curve")
	}
	if !pp.IsTorsionFree() {
		return nil, errs.NewFailed("point is not in correct subgroup")
	}

	return pp, nil
}

func (c *G2) Hash(bytes []byte) (*PointG2, error) {
	return c.HashWithDst(base.Hash2CurveAppTag+Hash2CurveSuiteG2, bytes)
}

func (c *G2) HashWithDst(dst string, bytes []byte) (*PointG2, error) {
	var p PointG2
	p.V.Hash(dst, bytes)
	return &p, nil
}

func (c *G2) ScalarStructure() algebra.Structure[*Scalar] {
	return NewScalarField()
}

func (c *G2) BaseStructure() algebra.Structure[*BaseFieldElementG2] {
	return NewG2BaseField()
}

func (c *G2) ScalarBaseOp(sc *Scalar) *PointG2 {
	if sc.IsZero() {
		return c.OpIdentity()
	}
	return c.ScalarBaseMul(sc)
}

func (c *G2) ScalarBaseMul(sc *Scalar) *PointG2 {
	return c.Generator().ScalarMul(sc)
}

type PointG2 struct {
	traits.PrimePointTrait[*bls12381Impl.Fp2, *bls12381Impl.G2Point, bls12381Impl.G2Point, *PointG2, PointG2]
}

func (p *PointG2) InSourceGroup() bool {
	return false
}

func (p *PointG2) Pair(p1 *PointG1) (*GtElement, error) {
	if p1 == nil {
		return nil, errs.NewArgument("cannot pair with nil G2 point")
	}
	ppe := NewOptimalAtePPE()
	if err := ppe.Add(p1, p); err != nil {
		return nil, errs.WrapFailed(err, "cannot add G1 and G2 points to pairing engine")
	}
	return ppe.Result(), nil
}

func (p *PointG2) MultiPair(with ...*PointG1) (*GtElement, error) {
	if len(with) == 0 {
		return nil, errs.NewArgument("cannot pair with empty G2 points")
	}

	ppe := NewOptimalAtePPE()
	for _, p1 := range with {
		if err := ppe.Add(p1, p); err != nil {
			return nil, errs.WrapFailed(err, "cannot add G1 and G2 points to pairing engine")
		}
	}
	return ppe.Result(), nil
}

func (p *PointG2) MultiPairAndInvertDuals(with ...*PointG1) (*GtElement, error) {
	if len(with) == 0 {
		return nil, errs.NewArgument("cannot pair with empty G2 points")
	}

	ppe := NewOptimalAtePPE()
	for _, p1 := range with {
		if err := ppe.AddAndInvG2(p1, p); err != nil {
			return nil, errs.WrapFailed(err, "cannot add G1 and G2 points to pairing engine")
		}
	}
	return ppe.Result(), nil
}

func (p *PointG2) HashCode() base.HashCode {
	h := fnv.New64a()
	_, _ = h.Write(p.ToCompressed())
	return base.HashCode(h.Sum64())
}

func (p *PointG2) Structure() algebra.Structure[*PointG2] {
	return NewG2()
}

func (p *PointG2) MarshalBinary() (data []byte, err error) {
	return p.ToCompressed(), nil
}

func (p *PointG2) UnmarshalBinary(data []byte) error {
	pp, err := NewG2().FromCompressed(data)
	if err != nil {
		return errs.WrapSerialisation(err, "cannot deserialize point")
	}
	p.V.Set(&pp.V)
	return nil
}

func (p *PointG2) Coordinates() algebra.Coordinates[*BaseFieldElementG2] {
	var x, y BaseFieldElementG2
	p.V.ToAffine(&x.V, &y.V)

	return algebra.Coordinates[*BaseFieldElementG2]{
		Value: []*BaseFieldElementG2{&x, &y},
		Name:  algebra.AffineCoordinateSystem,
	}
}

func (p *PointG2) ToCompressed() []byte {
	var x, y bls12381Impl.Fp2
	x.SetZero()
	y.SetZero()
	p.V.ToAffine(&x, &y)
	isInfinity := p.V.IsIdentity()

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

func (p *PointG2) ToUncompreseed() []byte {
	var x, y bls12381Impl.Fp2
	x.SetZero()
	y.SetZero()
	isInfinity := p.V.IsIdentity()
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

func (p *PointG2) AffineX() *BaseFieldElementG2 {
	if p.IsZero() {
		return NewG2BaseField().One()
	}

	var x, y BaseFieldElementG2
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		panic("this should never happen - failed to convert point to affine")
	}

	return &x
}

func (p *PointG2) AffineY() *BaseFieldElementG2 {
	if p.IsZero() {
		return NewG2BaseField().Zero()
	}

	var x, y BaseFieldElementG2
	if ok := p.V.ToAffine(&x.V, &y.V); ok == 0 {
		panic("this should never happen - failed to convert point to affine")
	}

	return &y
}

func (p *PointG2) ScalarOp(sc *Scalar) *PointG2 {
	return p.ScalarMul(sc)
}

func (p *PointG2) ScalarMul(actor *Scalar) *PointG2 {
	var result PointG2
	pointsImpl.ScalarMul[*bls12381Impl.Fp2](&result.V, &p.V, actor.V.Bytes())
	return &result
}

func (p *PointG2) IsTorsionFree() bool {
	// Ensure scalar field is initialized
	_ = NewScalarField()
	orderBytes := scalarFieldOrder.Bytes()
	slices.Reverse(orderBytes)
	var e bls12381Impl.G2Point
	pointsImpl.ScalarMul[*bls12381Impl.Fp2](&e, &p.V, orderBytes)
	return e.IsIdentity() == 1
}

func isNegative(v *bls12381Impl.Fp2) uint64 {
	c1Neg := fieldsImpl.IsNegative(&v.U1)
	c0Neg := fieldsImpl.IsNegative(&v.U0)
	c1Zero := v.U1.IsZero()

	return c1Neg | (c1Zero & c0Neg)
}
func (p *PointG2) Bytes() []byte {
	return p.ToCompressed()
}

func (p *PointG2) String() string {
	return traits.StringifyPoint(p)
}
