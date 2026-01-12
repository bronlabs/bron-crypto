package impl

import (
	"crypto/sha256"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
	h2c "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380/mappers/sswu"
)

var (
	_ pointsImpl.ShortWeierstrassCurveParams[*Fp] = curveParams{}
	_ h2c.HasherParams                            = CurveHasherParams{}
	_ sswu.NonZeroPointMapperParams[*Fp]          = curveMapperParams{}
	_ h2c.PointMapper[*Fp]                        = curveMapper{}
)

var (
	curveA               Fp
	curveB               Fp
	curveB3              Fp
	curveGx              Fp
	curveGy              Fp
	curveMessageExpander = h2c.NewXMDMessageExpander(sha256.New)

	sqrtRatioC1 = [...]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x3f}
	sqrtRatioC2 Fp

	sswuZ Fp
)

type curveParams struct{}

// CurveHasherParams defines hash-to-curve parameters.
type CurveHasherParams struct{}
type curveMapperParams struct{}
type curveMapper = sswu.NonZeroPointMapper[*Fp, curveMapperParams, Fp]

//nolint:gochecknoinits // curve params initialization
func init() {
	curveA.MustSetHex("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc")
	curveB.MustSetHex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")
	curveB3.MustSetHex("1052a18afeafbbb61bc3380063c994352f57141164fb12e2b36ab4ba777720e2")
	curveGx.MustSetHex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
	curveGy.MustSetHex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")

	sqrtRatioC2.MustSetHex("25ac71c31e27646736870398ae7f554d8472e008b3aa2a49d332cbd81bcc3b80")

	sswuZ.MustSetHex("ffffffff00000001000000000000000000000000fffffffffffffffffffffff5")
}

// ClearCofactor clears the cofactor of the input point.
func (curveParams) ClearCofactor(xOut, yOut, zOut, xIn, yIn, zIn *Fp) {
	xOut.Set(xIn)
	yOut.Set(yIn)
	zOut.Set(zIn)
}

// SetGenerator sets generator coordinates.
func (curveParams) SetGenerator(xOut, yOut, zOut *Fp) {
	xOut.Set(&curveGx)
	yOut.Set(&curveGy)
	zOut.SetOne()
}

// AddA adds the curve A parameter to in.
func (curveParams) AddA(out, in *Fp) {
	out.Add(in, &curveA)
}

// AddB adds the curve B parameter to in.
func (curveParams) AddB(out, in *Fp) {
	out.Add(in, &curveB)
}

// MulByA multiples provided element by -3 (p256 a=-3).
func (curveParams) MulByA(out *Fp, in *Fp) {
	var n1, n2 Fp
	n1.Neg(in)        // -1
	n2.Add(&n1, &n1)  // -2
	out.Add(&n1, &n2) // -3
}

// MulBy3B multiples provided element by 3*b.
func (curveParams) MulBy3B(out *Fp, in *Fp) {
	out.Mul(in, &curveB3)
}

// L returns the hash-to-field length in bytes.
func (CurveHasherParams) L() uint64 {
	return 48
}

// MessageExpander returns the RFC 9380 message expander.
func (CurveHasherParams) MessageExpander() h2c.MessageExpander {
	return curveMessageExpander
}

// MulByA multiplies by the curve A parameter.
func (curveMapperParams) MulByA(out, in *Fp) {
	var n1, n2 Fp
	n1.Neg(in)        // -1
	n2.Add(&n1, &n1)  // -2
	out.Add(&n1, &n2) // -3
}

// MulByB multiplies by the curve B parameter.
func (curveMapperParams) MulByB(out, in *Fp) {
	out.Mul(in, &curveB)
}

// SetZ sets the SSWU Z parameter.
func (curveMapperParams) SetZ(out *Fp) {
	out.Set(&sswuZ)
}

// SqrtRatio computes sqrt(u/v) with curve-specific parameters.
func (curveMapperParams) SqrtRatio(y, u, v *Fp) (ok ct.Bool) {
	return sswu.SqrtRatio3Mod4(y, sqrtRatioC1[:], &sqrtRatioC2, u, v)
}

// Sgn0 returns the sign bit per RFC 9380.
func (curveMapperParams) Sgn0(v *Fp) ct.Bool {
	return ct.Bool(uint64(v.Bytes()[0] & 0b1))
}
