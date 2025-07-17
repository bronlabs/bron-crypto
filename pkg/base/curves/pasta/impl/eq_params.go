package impl

import (
	"hash"

	"golang.org/x/crypto/blake2b"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
	h2c "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380/mappers/sswu"
)

var (
	_ pointsImpl.ShortWeierstrassCurveParams[*Fq] = vestaCurveParams{}
	_ h2c.HasherParams                            = VestaCurveHasherParams{}
	_ sswu.ZeroPointMapperParams[*Fq, Fq]         = vestaCurveMapperParams{}
	_ h2c.PointMapper[*Fq]                        = vestaCurveMapper{}
)

var (
	vestaCurveB               Fq
	vestaCurveGy              Fq
	vestaCurveMessageExpander = h2c.NewXMDMessageExpander(func() hash.Hash { h, _ := blake2b.New512(nil); return h })

	vestaSqrtRatioC1 = uint64(32)
	vestaSqrtRatioC3 = [...]uint8{0x90, 0x75, 0x23, 0xc6, 0x6e, 0x54, 0xca, 0x04, 0x7e, 0x4c, 0x23, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20}
	vestaSqrtRatioC4 = uint64((1 << vestaSqrtRatioC1) - 1)
	vestaSqrtRatioC5 = uint64(1 << (vestaSqrtRatioC1 - 1))
	vestaSqrtRatioC6 Fq
	vestaSqrtRatioC7 Fq

	vestaSswuZ           Fq
	vestaSswuIsogenyA    Fq
	vestaSswuIsogenyB    Fq
	vestaSswuIsogenyXNum [4]Fq
	vestaSswuIsogenyXDen [3]Fq
	vestaSswuIsogenyYNum [4]Fq
	vestaSswuIsogenyYDen [4]Fq
)

type vestaCurveParams struct{}
type VestaCurveHasherParams struct{}
type vestaCurveMapperParams struct{}
type vestaCurveMapper = sswu.ZeroPointMapper[*Fq, vestaCurveMapperParams, Fq]

//nolint:gochecknoinits // curve params initialization
func init() {
	vestaCurveB.MustSetHex("0000000000000000000000000000000000000000000000000000000000000005")
	vestaCurveGy.MustSetHex("1943666ea922ae6b13b64e3aae89754cacce3a7f298ba20c4e4389b9b0276a62")

	vestaSqrtRatioC6.MustSetHex("16915a9e3a85ecaa11685fd036be6bf8870326a1c5e594f7be27d905dd4b42e0")
	vestaSqrtRatioC7.MustSetHex("2f5b4405e8f664f4cc83ce90eb785a677d2c72c8b07779a471604d7507c718f6")

	vestaSswuZ.MustSetHex("40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffff4")
	vestaSswuIsogenyA.MustSetHex("267f9b2ee592271a81639c4d96f787739673928c7d01b212c515ad7242eaa6b1")
	vestaSswuIsogenyB.MustSetHex("00000000000000000000000000000000000000000000000000000000000004f1")
	vestaSswuIsogenyXNum[0].MustSetHex("31c71c71c71c71c71c71c71c71c71c71e1c521a795ac8356fb539a6f0000002b")
	vestaSswuIsogenyXNum[1].MustSetHex("18760c7f7a9ad20ded7ee4a9cdf78f8fd59d03d23b39cb11aeac67bbeb586a3d")
	vestaSswuIsogenyXNum[2].MustSetHex("1d935247b4473d17acecf10f5f7c09a2216b8861ec72bd5d8b95c6aaf703bcc5")
	vestaSswuIsogenyXNum[3].MustSetHex("38e38e38e38e38e38e38e38e38e38e390205dd51cfa0961a43cd42c800000001")
	vestaSswuIsogenyXDen[0].MustSetHex("14735171ee5427780c621de8b91c242a30cd6d53df49d235f169c187d2533465")
	vestaSswuIsogenyXDen[1].MustSetHex("0a2de485568125d51454798a5b5c56b2a3ad678129b604d3b7284f7eaf21a2e9")
	vestaSswuIsogenyXDen[2].SetOne()
	vestaSswuIsogenyYNum[0].MustSetHex("1ed097b425ed097b425ed097b425ed098bc32d36fb21a6a38f64842c55555533")
	vestaSswuIsogenyYNum[1].MustSetHex("19b0d87e16e2578866d1466e9de10e6497a3ca5c24e9ea634986913ab4443034")
	vestaSswuIsogenyYNum[2].MustSetHex("2ec9a923da239e8bd6767887afbe04d121d910aefb03b31d8bee58e5fb81de63")
	vestaSswuIsogenyYNum[3].MustSetHex("12f684bda12f684bda12f684bda12f685601f4709a8adcb36bef1642aaaaaaab")
	vestaSswuIsogenyYDen[0].MustSetHex("40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffde5")
	vestaSswuIsogenyYDen[1].MustSetHex("3d59f455cafc7668252659ba2b546c7e926847fb9ddd76a1d43d449776f99d2f")
	vestaSswuIsogenyYDen[2].MustSetHex("2f44d6c801c1b8bf9e7eb64f890a820c06a767bfc35b5bac58dfecce86b2745e")
	vestaSswuIsogenyYDen[3].SetOne()
}

func (vestaCurveParams) ClearCofactor(xOut, yOut, zOut, xIn, yIn, zIn *Fq) {
	xOut.Set(xIn)
	yOut.Set(yIn)
	zOut.Set(zIn)
}

func (vestaCurveParams) SetGenerator(xOut, yOut, zOut *Fq) {
	xOut.SetOne()
	yOut.Set(&vestaCurveGy)
	zOut.SetOne()
}

func (vestaCurveParams) AddA(out, in *Fq) {
	out.Set(in)
}

func (vestaCurveParams) AddB(out, in *Fq) {
	out.Add(in, &vestaCurveB)
}

// MulByA multiples provided element by 0 (vesta a=0).
func (vestaCurveParams) MulByA(out *Fq, _ *Fq) {
	out.SetZero()
}

// MulBy3B multiples provided element by 15 (vesta b=5, hence 3*5 = 15).
func (vestaCurveParams) MulBy3B(out *Fq, in *Fq) {
	var in2, in4, in8, in16 Fq
	in2.Add(in, in)
	in4.Add(&in2, &in2)
	in8.Add(&in4, &in4)
	in16.Add(&in8, &in8)
	out.Sub(&in16, in)
}

func (VestaCurveHasherParams) L() uint64 {
	return 64
}

func (VestaCurveHasherParams) MessageExpander() h2c.MessageExpander {
	return vestaCurveMessageExpander
}

func (vestaCurveMapperParams) MulByA(out, in *Fq) {
	out.Mul(in, &vestaSswuIsogenyA)
}

func (vestaCurveMapperParams) MulByB(out, in *Fq) {
	out.Mul(in, &vestaSswuIsogenyB)
}

func (vestaCurveMapperParams) SetZ(out *Fq) {
	out.Set(&vestaSswuZ)
}

func (vestaCurveMapperParams) SqrtRatio(y, u, v *Fq) (ok ct.Bool) {
	return sswu.SqrtRatio(y, vestaSqrtRatioC1, vestaSqrtRatioC3[:], vestaSqrtRatioC4, vestaSqrtRatioC5, &vestaSqrtRatioC6, &vestaSqrtRatioC7, u, v)
}

func (vestaCurveMapperParams) Sgn0(v *Fq) ct.Bool {
	return ct.Bool(uint64(v.Bytes()[0] & 0b1))
}

func (vestaCurveMapperParams) XNum() []Fq {
	return vestaSswuIsogenyXNum[:]
}

func (vestaCurveMapperParams) XDen() []Fq {
	return vestaSswuIsogenyXDen[:]
}

func (vestaCurveMapperParams) YNum() []Fq {
	return vestaSswuIsogenyYNum[:]
}

func (vestaCurveMapperParams) YDen() []Fq {
	return vestaSswuIsogenyYDen[:]
}
