package impl

import (
	"crypto/sha512"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/h2c"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/h2c/mappers/elligator2"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/points"
)

var (
	_ points.TwistedEdwardsCurveParams[*Fp] = curveParams{}
	_ h2c.HasherParams                      = CurveHasherParams{}
	_ h2c.PointMapper[*Fp]                  = curveMapper{}

	curveA               Fp
	curveD               Fp
	curveD2              Fp
	curveGx              Fp
	curveGy              Fp
	curveGxy             Fp
	curveMessageExpander = h2c.NewXMDMessageExpander(sha512.New)
)

//nolint:gochecknoinits // parameters initialization
func init() {
	curveA.MustSetHex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec")
	curveD.MustSetHex("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3")
	curveD2.MustSetHex("2406d9dc56dffce7198e80f2eef3d13000e0149a8283b156ebd69b9426b2f159")
	curveGx.MustSetHex("216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A")
	curveGy.MustSetHex("6666666666666666666666666666666666666666666666666666666666666658")
	curveGxy.Mul(&curveGx, &curveGy)
}

type curveParams struct{}

type CurveHasherParams struct{}

type curveMapper = elligator2.Edwards25519PointMapper[*Fp, Fp]

func (curveParams) SetGenerator(xOut, yOut, tOut, zOut *Fp) {
	xOut.Set(&curveGx)
	yOut.Set(&curveGy)
	tOut.Set(&curveGxy)
	zOut.SetOne()
}

func (curveParams) ClearCofactor(xOut, yOut, tOut, zOut, xIn, yIn, tIn, zIn *Fp) {
	var out Point
	out.X.Set(xIn)
	out.Y.Set(yIn)
	out.T.Set(tIn)
	out.Z.Set(zIn)
	out.Double(&out)
	out.Double(&out)
	out.Double(&out)

	xOut.Set(&out.X)
	yOut.Set(&out.Y)
	tOut.Set(&out.T)
	zOut.Set(&out.Z)
}

func (curveParams) SetA(out *Fp) {
	out.Set(&curveA)
}

func (curveParams) MulByA(out, in *Fp) {
	out.Neg(in)
}

func (curveParams) MulByD(out, in *Fp) {
	out.Mul(in, &curveD)
}

func (curveParams) MulBy2D(out, in *Fp) {
	out.Mul(in, &curveD2)
}

func (CurveHasherParams) L() uint64 {
	return 48
}

func (CurveHasherParams) MessageExpander() h2c.MessageExpander {
	return curveMessageExpander
}
