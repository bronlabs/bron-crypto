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
	_ sswu.ZeroPointMapperParams[*Fp, Fp]         = curveMapperParams{}
	_ h2c.PointMapper[*Fp]                        = curveMapper{}
)

var (
	curveB               Fp
	curveB3              Fp
	curveGx              Fp
	curveGy              Fp
	curveMessageExpander = h2c.NewXMDMessageExpander(sha256.New)

	sqrtRatioC1 = [...]uint8{0x0b, 0xff, 0xff, 0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f}
	sqrtRatioC2 Fp

	sswuZ           Fp
	sswuIsogenyA    Fp
	sswuIsogenyB    Fp
	sswuIsogenyXNum [4]Fp
	sswuIsogenyXDen [3]Fp
	sswuIsogenyYNum [4]Fp
	sswuIsogenyYDen [4]Fp
)

type curveParams struct{}
type CurveHasherParams struct{}
type curveMapperParams struct{}
type curveMapper = sswu.ZeroPointMapper[*Fp, curveMapperParams, Fp]

//nolint:gochecknoinits // keep for static parameters
func init() {
	curveB.MustSetHex("0000000000000000000000000000000000000000000000000000000000000007")
	curveB3.MustSetHex("0000000000000000000000000000000000000000000000000000000000000015")
	curveGx.MustSetHex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	curveGy.MustSetHex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")

	sqrtRatioC2.MustSetHex("31fdf302724013e57ad13fb38f842afeec184f00a74789dd286729c8303c4a59")

	sswuZ.MustSetHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc24")
	sswuIsogenyA.MustSetHex("3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533")
	sswuIsogenyB.MustSetHex("00000000000000000000000000000000000000000000000000000000000006eb")
	sswuIsogenyXNum[0].MustSetHex("8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa8c7")
	sswuIsogenyXNum[1].MustSetHex("07d3d4c80bc321d5b9f315cea7fd44c5d595d2fc0bf63b92dfff1044f17c6581")
	sswuIsogenyXNum[2].MustSetHex("534c328d23f234e6e2a413deca25caece4506144037c40314ecbd0b53d9dd262")
	sswuIsogenyXNum[3].MustSetHex("8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa88c")
	sswuIsogenyXDen[0].MustSetHex("d35771193d94918a9ca34ccbb7b640dd86cd409542f8487d9fe6b745781eb49b")
	sswuIsogenyXDen[1].MustSetHex("edadc6f64383dc1df7c4b2d51b54225406d36b641f5e41bbc52a56612a8c6d14")
	sswuIsogenyXDen[2].SetOne()
	sswuIsogenyYNum[0].MustSetHex("4bda12f684bda12f684bda12f684bda12f684bda12f684bda12f684b8e38e23c")
	sswuIsogenyYNum[1].MustSetHex("c75e0c32d5cb7c0fa9d0a54b12a0a6d5647ab046d686da6fdffc90fc201d71a3")
	sswuIsogenyYNum[2].MustSetHex("29a6194691f91a73715209ef6512e576722830a201be2018a765e85a9ecee931")
	sswuIsogenyYNum[3].MustSetHex("2f684bda12f684bda12f684bda12f684bda12f684bda12f684bda12f38e38d84")
	sswuIsogenyYDen[0].MustSetHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffff93b")
	sswuIsogenyYDen[1].MustSetHex("7a06534bb8bdb49fd5e9e6632722c2989467c1bfc8e8d978dfb425d2685c2573")
	sswuIsogenyYDen[2].MustSetHex("6484aa716545ca2cf3a70c3fa8fe337e0a3d21162f0d6299a7bf8192bfd2a76f")
	sswuIsogenyYDen[3].SetOne()
}

func (curveParams) SetGenerator(xOut, yOut, zOut *Fp) {
	xOut.Set(&curveGx)
	yOut.Set(&curveGy)
	zOut.SetOne()
}

func (curveParams) ClearCofactor(xOut, yOut, zOut, xIn, yIn, zIn *Fp) {
	xOut.Set(xIn)
	yOut.Set(yIn)
	zOut.Set(zIn)
}

// MulByA multiples provided element by 0 (secp256k1 a=0).
func (curveParams) MulByA(out *Fp, _ *Fp) {
	out.SetZero()
}

// MulBy3B multiples provided element by 21 (secp256k1 b=7, hence 3*7 = 21).
func (curveParams) MulBy3B(out *Fp, in *Fp) {
	out.Mul(in, &curveB3)
}

func (curveParams) AddA(out *Fp, in *Fp) {
	out.Set(in)
}

func (curveParams) AddB(out *Fp, in *Fp) {
	out.Add(in, &curveB)
}

func (CurveHasherParams) L() uint64 {
	return 48
}

func (CurveHasherParams) MessageExpander() h2c.MessageExpander {
	return curveMessageExpander
}

func (curveMapperParams) MulByA(out, in *Fp) {
	out.Mul(in, &sswuIsogenyA)
}

func (curveMapperParams) MulByB(out, in *Fp) {
	out.Mul(in, &sswuIsogenyB)
}

func (curveMapperParams) SetZ(out *Fp) {
	out.Set(&sswuZ)
}

func (curveMapperParams) SqrtRatio(y, u, v *Fp) (ok ct.Bool) {
	return sswu.SqrtRatio3Mod4(y, sqrtRatioC1[:], &sqrtRatioC2, u, v)
}

func (curveMapperParams) Sgn0(v *Fp) ct.Bool {
	return ct.Bool(uint64(v.Bytes()[0] & 0b1))
}

func (curveMapperParams) XNum() []Fp {
	return sswuIsogenyXNum[:]
}

func (curveMapperParams) XDen() []Fp {
	return sswuIsogenyXDen[:]
}

func (curveMapperParams) YNum() []Fp {
	return sswuIsogenyYNum[:]
}

func (curveMapperParams) YDen() []Fp {
	return sswuIsogenyYDen[:]
}
