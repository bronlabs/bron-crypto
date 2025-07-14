package impl

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380/mappers/sswu"
	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
)

var (
	_ pointsImpl.ShortWeierstrassCurveParams[*Fp2] = g2CurveParams{}
	_ h2c.HasherParams                             = G2CurveHasherParams{}
	_ sswu.ZeroPointMapperParams[*Fp2, Fp2]        = g2CurveMapperParams{}
)

var (
	g2CurveB               Fp2
	g2CurveGx              Fp2
	g2CurveGy              Fp2
	g2CurveMessageExpander = h2c.NewXMDMessageExpander(sha256.New)

	g2PsiC1  Fp2
	g2PsiC2  Fp2
	g2Psi2C1 Fp2

	g2SqrtRatioC1 = uint64(3)
	g2SqrtRatioC3 = [...]uint8{0xe3, 0x18, 0xc7, 0x01, 0x00, 0xa0, 0x6a, 0xb2, 0xea, 0x82, 0x63, 0xd7, 0xb1, 0xd6, 0xce, 0xd7, 0xcf, 0x13, 0x21, 0x36, 0x38, 0xc3, 0x62, 0x31, 0x74, 0x1b, 0xe7, 0xd3, 0x1e, 0xf9, 0x6b, 0x96, 0x04, 0x1a, 0x09, 0x87, 0x5a, 0xe8, 0x92, 0xb2, 0xc7, 0x85, 0x61, 0xc8, 0x19, 0x86, 0xd6, 0x11, 0xf0, 0x8e, 0x97, 0x30, 0x93, 0x14, 0x53, 0xef, 0xa6, 0xdc, 0x6d, 0xd1, 0xcf, 0x62, 0x0a, 0x05, 0xbd, 0xe8, 0x49, 0x93, 0xe4, 0x59, 0x6e, 0x46, 0x6b, 0x04, 0xe7, 0x50, 0x0e, 0xc9, 0x2d, 0x9e, 0x5e, 0xf2, 0x22, 0xaa, 0x8e, 0x27, 0xbd, 0x74, 0xfc, 0x35, 0x8c, 0x4b, 0x7a, 0x43, 0x2a}
	g2SqrtRatioC4 = uint64((1 << g2SqrtRatioC1) - 1)
	g2SqrtRatioC5 = uint64(1 << (g2SqrtRatioC1 - 1))
	g2SqrtRatioC6 Fp2
	g2SqrtRatioC7 Fp2

	g2SswuZ           Fp2
	g2SswuIsogenyA    Fp2
	g2SswuIsogenyB    Fp2
	g2SswuIsogenyXNum [4]Fp2
	g2SswuIsogenyXDen [3]Fp2
	g2SswuIsogenyYNum [4]Fp2
	g2SswuIsogenyYDen [4]Fp2
)

//nolint:gochecknoinits // curve params initialization
func init() {
	g2CurveB.U0.MustSetHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004")
	g2CurveB.U1.MustSetHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004")
	g2CurveGx.U0.MustSetHex("024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8")
	g2CurveGx.U1.MustSetHex("13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e")
	g2CurveGy.U0.MustSetHex("0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801")
	g2CurveGy.U1.MustSetHex("0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be")

	g2PsiC1.U0.SetZero()
	g2PsiC1.U1.MustSetHex("1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad")
	g2PsiC2.U0.MustSetHex("135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2")
	g2PsiC2.U1.MustSetHex("06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09")
	g2Psi2C1.U0.MustSetHex("1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac")
	g2Psi2C1.U1.SetZero()

	g2SqrtRatioC6.U0.MustSetHex("06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09")
	g2SqrtRatioC6.U1.MustSetHex("06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09")
	g2SqrtRatioC7.U0.MustSetHex("13dc0969311e2ba565924cb0b6f7bb9857f157e17f0c8db4e484fcb27b8be0b36dfa0340c422fb7efe9d9a3234336d5e")
	g2SqrtRatioC7.U1.MustSetHex("071d42ac9c54001a21acf9187d469d919a830a2c969128d22659dc2f8263f1ca73c5b0e02c05ec381b8684a676a81381")

	g2SswuZ.U0.MustSetHex("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaa9")
	g2SswuZ.U1.MustSetHex("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa")
	g2SswuIsogenyA.U0.MustSetHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	g2SswuIsogenyA.U1.MustSetHex("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f0")
	g2SswuIsogenyB.U0.MustSetHex("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003f4")
	g2SswuIsogenyB.U1.MustSetHex("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003f4")
	g2SswuIsogenyXNum[0].U0.MustSetHex("05c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6")
	g2SswuIsogenyXNum[0].U1.MustSetHex("05c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6")
	g2SswuIsogenyXNum[1].U0.MustSetHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	g2SswuIsogenyXNum[1].U1.MustSetHex("11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a")
	g2SswuIsogenyXNum[2].U0.MustSetHex("11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e")
	g2SswuIsogenyXNum[2].U1.MustSetHex("08ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d")
	g2SswuIsogenyXNum[3].U0.MustSetHex("171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1")
	g2SswuIsogenyXNum[3].U1.MustSetHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	g2SswuIsogenyXDen[0].U0.MustSetHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	g2SswuIsogenyXDen[0].U1.MustSetHex("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63")
	g2SswuIsogenyXDen[1].U0.MustSetHex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c")
	g2SswuIsogenyXDen[1].U1.MustSetHex("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f")
	g2SswuIsogenyXDen[2].SetOne()
	g2SswuIsogenyYNum[0].U0.MustSetHex("1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706")
	g2SswuIsogenyYNum[0].U1.MustSetHex("1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706")
	g2SswuIsogenyYNum[1].U0.MustSetHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	g2SswuIsogenyYNum[1].U1.MustSetHex("05c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be")
	g2SswuIsogenyYNum[2].U0.MustSetHex("11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c")
	g2SswuIsogenyYNum[2].U1.MustSetHex("08ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f")
	g2SswuIsogenyYNum[3].U0.MustSetHex("124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10")
	g2SswuIsogenyYNum[3].U1.MustSetHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	g2SswuIsogenyYDen[0].U0.MustSetHex("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb")
	g2SswuIsogenyYDen[0].U1.MustSetHex("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb")
	g2SswuIsogenyYDen[1].U0.MustSetHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	g2SswuIsogenyYDen[1].U1.MustSetHex("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3")
	g2SswuIsogenyYDen[2].U0.MustSetHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012")
	g2SswuIsogenyYDen[2].U1.MustSetHex("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99")
	g2SswuIsogenyYDen[3].SetOne()
}

type g2CurveParams struct{}
type G2CurveHasherParams struct{}
type g2CurveMapperParams struct{}
type g2CurveMapper = sswu.ZeroPointMapper[*Fp2, g2CurveMapperParams, Fp2]

func (g2CurveParams) AddA(out, in *Fp2) {
	out.Set(in)
}

func (g2CurveParams) AddB(out, in *Fp2) {
	out.Add(in, &g2CurveB)
}

func (g2CurveParams) MulByA(out, _ *Fp2) {
	out.SetZero()
}

// MulBy3B where B = 4(u+1).
func (g2CurveParams) MulBy3B(out, in *Fp2) {
	var params fp2Params
	var c, c2, c4, c8 Fp2
	c.U1.Add(&in.U0, &in.U1)
	params.MulByQuadraticNonResidue(&c.U0, &in.U1)
	c.U0.Add(&c.U0, &in.U0)
	c2.Add(&c, &c)
	c4.Add(&c2, &c2)
	c8.Add(&c4, &c4)

	out.Add(&c4, &c8) // out = 3 * 4(u+1)
}

func (g2CurveParams) ClearCofactor(xOut, yOut, zOut, xIn, yIn, zIn *Fp2) {
	var out, in G2Point
	in.X.Set(xIn)
	in.Y.Set(yIn)
	in.Z.Set(zIn)

	clearCofactorBls12381G2(&out, &in)
	xOut.Set(&out.X)
	yOut.Set(&out.Y)
	zOut.Set(&out.Z)
}

func (g2CurveParams) SetGenerator(xOut, yOut, zOut *Fp2) {
	xOut.Set(&g2CurveGx)
	yOut.Set(&g2CurveGy)
	zOut.SetOne()
}

func (G2CurveHasherParams) M() uint64 {
	return 2
}

func (G2CurveHasherParams) L() uint64 {
	return 64
}

func (G2CurveHasherParams) MessageExpander() h2c.MessageExpander {
	return g2CurveMessageExpander
}

func (G2CurveHasherParams) Suite() []byte {
	return []byte("BLS12381G2_XMD:SHA-256_SSWU_RO_")
}

func (g2CurveMapperParams) MulByA(out, in *Fp2) {
	out.Mul(in, &g2SswuIsogenyA)
}

func (g2CurveMapperParams) MulByB(out, in *Fp2) {
	out.Mul(in, &g2SswuIsogenyB)
}

func (g2CurveMapperParams) SetZ(out *Fp2) {
	out.Set(&g2SswuZ)
}

func (g2CurveMapperParams) SqrtRatio(out, u, v *Fp2) (ok uint64) {
	return sswu.SqrtRatio(out, g2SqrtRatioC1, g2SqrtRatioC3[:], g2SqrtRatioC4, g2SqrtRatioC5, &g2SqrtRatioC6, &g2SqrtRatioC7, u, v)
}

func (g2CurveMapperParams) Sgn0(v *Fp2) uint64 {
	// 1. sign_0 = x_0 mod 2
	sign0 := uint64(v.U0.Bytes()[0] & 0b1)
	// 2. zero_0 = x_0 == 0
	zero0 := v.U0.IsZero()
	// 3. sign_1 = x_1 mod 2
	sign1 := uint64(v.U1.Bytes()[0] & 0b1)
	// 4. s = sign_0 OR (zero_0 AND sign_1) # Avoid short-circuit logic ops
	s := sign0 | (zero0 & sign1)
	// 5. return s
	return s
}

func (g2CurveMapperParams) XNum() []Fp2 {
	return g2SswuIsogenyXNum[:]
}

func (g2CurveMapperParams) XDen() []Fp2 {
	return g2SswuIsogenyXDen[:]
}

func (g2CurveMapperParams) YNum() []Fp2 {
	return g2SswuIsogenyYNum[:]
}

func (g2CurveMapperParams) YDen() []Fp2 {
	return g2SswuIsogenyYDen[:]
}

func frobenius(out, in *Fp2) {
	var a Fp2

	// 1. a = x0 - I * x1
	a.U0.Set(&in.U0)
	a.U1.Neg(&in.U1)
	// 2. return a
	out.Set(&a)
}

func psi(out, in *G2Point) {
	var q G2Point

	// 1. qxn = c1 * frobenius(xn)
	frobenius(&q.X, &in.X)
	q.X.Mul(&g2PsiC1, &q.X)

	// 2. qxd = frobenius(xd)
	// 4. qyd = frobenius(yd)
	frobenius(&q.Z, &in.Z)

	// 3. qyn = c2 * frobenius(yn)
	frobenius(&q.Y, &in.Y)
	q.Y.Mul(&g2PsiC2, &q.Y)

	// 5. return (qxn, qxd, qyn, qyd)
	out.Set(&q)
}

func psi2(out, in *G2Point) {
	var q G2Point

	// 1. qxn = c1 * xn
	q.X.Mul(&g2Psi2C1, &in.X)

	// 2. qyn = -yn
	q.Y.Neg(&in.Y)

	// 3. return (qxn, xd, qyn, yd)
	q.Z.Set(&in.Z)
	out.Set(&q)
}

func clearCofactorBls12381G2(out, in *G2Point) {
	var t1, t2, t3, q G2Point

	// 1.  t1 = c1 * P
	pointsImpl.ScalarMul[*Fp2](&t1, in, binary.LittleEndian.AppendUint64(nil, X))
	t1.Neg(&t1)

	// 2.  t2 = psi(P)
	psi(&t2, in)

	// 3.  t3 = 2 * P
	t3.Double(in)

	// 4.  t3 = psi2(t3)
	psi2(&t3, &t3)

	// 5.  t3 = t3 - t2
	t3.Sub(&t3, &t2)

	// 6.  t2 = t1 + t2
	t2.Add(&t1, &t2)

	// 7.  t2 = c1 * t2
	pointsImpl.ScalarMul[*Fp2](&t2, &t2, binary.LittleEndian.AppendUint64(nil, X))
	t2.Neg(&t2)

	// 8.  t3 = t3 + t2
	t3.Add(&t3, &t2)

	// 9.  t3 = t3 - t1
	t3.Sub(&t3, &t1)

	// 10.  Q = t3 - P
	q.Sub(&t3, in)

	// 11. return Q
	out.Set(&q)
}
