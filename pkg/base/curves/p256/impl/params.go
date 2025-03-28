package impl

import (
	"crypto/sha256"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/h2c"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/h2c/mappers/sswu"
	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
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

func (curveParams) ClearCofactor(xOut, yOut, zOut, xIn, yIn, zIn *Fp) {
	xOut.Set(xIn)
	yOut.Set(yIn)
	zOut.Set(zIn)
}

func (curveParams) SetGenerator(xOut, yOut, zOut *Fp) {
	xOut.Set(&curveGx)
	yOut.Set(&curveGy)
	zOut.SetOne()
}

func (curveParams) AddA(out, in *Fp) {
	out.Add(in, &curveA)
}

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

func (CurveHasherParams) L() uint64 {
	return 48
}

func (CurveHasherParams) MessageExpander() h2c.MessageExpander {
	return curveMessageExpander
}

func (curveMapperParams) MulByA(out, in *Fp) {
	var n1, n2 Fp
	n1.Neg(in)        // -1
	n2.Add(&n1, &n1)  // -2
	out.Add(&n1, &n2) // -3
}

func (curveMapperParams) MulByB(out, in *Fp) {
	out.Mul(in, &curveB)
}

func (curveMapperParams) SetZ(out *Fp) {
	out.Set(&sswuZ)
}

func (curveMapperParams) SqrtRatio(y, u, v *Fp) (ok uint64) {
	return sswu.SqrtRatio3Mod4(y, sqrtRatioC1[:], &sqrtRatioC2, u, v)
}

func (curveMapperParams) Sgn0(v *Fp) uint64 {
	return uint64(v.Bytes()[0] & 0b1)
}
