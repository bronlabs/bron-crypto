package impl

import (
	"hash"

	"golang.org/x/crypto/blake2b"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/h2c"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/h2c/mappers/sswu"
	pointsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/points"
)

var (
	_ pointsImpl.ShortWeierstrassCurveParams[*Fp] = pallasCurveParams{}
	_ h2c.HasherParams                            = PallasCurveHasherParams{}
	_ sswu.ZeroPointMapperParams[*Fp, Fp]         = pallasCurveMapperParams{}
	_ h2c.PointMapper[*Fp]                        = pallasCurveMapper{}
)

var (
	pallasCurveB          Fp
	pallasCurveMinaGy     Fp
	pallasMessageExpander = h2c.NewXMDMessageExpander(func() hash.Hash { h, _ := blake2b.New512(nil); return h })

	pallasSqrtRatioC1 = uint64(32)
	pallasSqrtRatioC3 = [...]uint8{0x76, 0x98, 0x96, 0xcc, 0x8d, 0x7c, 0xa6, 0x04, 0x7e, 0x4c, 0x23, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20}
	pallasSqrtRatioC4 = uint64((1 << pallasSqrtRatioC1) - 1)
	pallasSqrtRatioC5 = uint64(1 << (pallasSqrtRatioC1 - 1))
	pallasSqrtRatioC6 Fp
	pallasSqrtRatioC7 Fp

	pallasSswuZ           Fp
	pallasSswuIsogenyA    Fp
	pallasSswuIsogenyB    Fp
	pallasSswuIsogenyXNum [4]Fp
	pallasSswuIsogenyXDen [3]Fp
	pallasSswuIsogenyYNum [4]Fp
	pallasSswuIsogenyYDen [4]Fp
)

type pallasCurveParams struct{}
type PallasCurveHasherParams struct{}

func (PallasCurveHasherParams) L() uint64 {
	return 64
}

func (PallasCurveHasherParams) MessageExpander() h2c.MessageExpander {
	return pallasMessageExpander
}

type pallasCurveMapperParams struct{}
type pallasCurveMapper = sswu.ZeroPointMapper[*Fp, pallasCurveMapperParams, Fp]

//nolint:gochecknoinits // curve params initialization
func init() {
	pallasCurveB.MustSetHex("0000000000000000000000000000000000000000000000000000000000000005")
	pallasCurveMinaGy.MustSetHex("1b74b5a30a12937c53dfa9f06378ee548f655bd4333d477119cf7a23caed2abb")

	pallasSqrtRatioC6.MustSetHex("3532c03204fba871900f0174278bfa48a84bde8a976e4e47a58f2ab23e9ea126")
	pallasSqrtRatioC7.MustSetHex("3dc271c8308fca72f0b7a1a19440ccc7325f98710655bac58f7f70a4ccefc9e9")

	pallasSswuZ.MustSetHex("40000000000000000000000000000000224698fc094cf91b992d30ecfffffff4")
	pallasSswuIsogenyA.MustSetHex("18354a2eb0ea8c9c49be2d7258370742b74134581a27a59f92bb4b0b657a014b")
	pallasSswuIsogenyB.MustSetHex("00000000000000000000000000000000000000000000000000000000000004f1")
	pallasSswuIsogenyXNum[0].MustSetHex("1c71c71c71c71c71c71c71c71c71c71c8102eea8e7b06eb6eebec06955555580")
	pallasSswuIsogenyXNum[1].MustSetHex("17329b9ec525375398c7d7ac3d98fd13380af066cfeb6d690eb64faef37ea4f7")
	pallasSswuIsogenyXNum[2].MustSetHex("3509afd51872d88e267c7ffa51cf412a0f93b82ee4b994958cf863b02814fb76")
	pallasSswuIsogenyXNum[3].MustSetHex("0e38e38e38e38e38e38e38e38e38e38e4081775473d8375b775f6034aaaaaaab")
	pallasSswuIsogenyXDen[0].MustSetHex("325669becaecd5d11d13bf2a7f22b105b4abf9fb9a1fc81c2aa3af1eae5b6604")
	pallasSswuIsogenyXDen[1].MustSetHex("1d572e7ddc099cff5a607fcce0494a799c434ac1c96b6980c47f2ab668bcd71f")
	pallasSswuIsogenyXDen[2].SetOne()
	pallasSswuIsogenyYNum[0].MustSetHex("025ed097b425ed097b425ed097b425ed0ac03e8e134eb3e493e53ab371c71c4f")
	pallasSswuIsogenyYNum[1].MustSetHex("3fb98ff0d2ddcadd303216cce1db9ff11765e924f745937802e2be87d225b234")
	pallasSswuIsogenyYNum[2].MustSetHex("1a84d7ea8c396c47133e3ffd28e7a09507c9dc17725cca4ac67c31d8140a7dbb")
	pallasSswuIsogenyYNum[3].MustSetHex("1a12f684bda12f684bda12f684bda12f7642b01ad461bad25ad985b5e38e38e4")
	pallasSswuIsogenyYDen[0].MustSetHex("40000000000000000000000000000000224698fc094cf91b992d30ecfffffde5")
	pallasSswuIsogenyYDen[1].MustSetHex("17033d3c60c68173573b3d7f7d681310d976bbfabbc5661d4d90ab820b12320a")
	pallasSswuIsogenyYDen[2].MustSetHex("0c02c5bcca0e6b7f0790bfb3506defb65941a3a4a97aa1b35a28279b1d1b42ae")
	pallasSswuIsogenyYDen[3].SetOne()
}

func (pallasCurveParams) ClearCofactor(xOut, yOut, zOut, xIn, yIn, zIn *Fp) {
	xOut.Set(xIn)
	yOut.Set(yIn)
	zOut.Set(zIn)
}

func (pallasCurveParams) SetGenerator(xOut, yOut, zOut *Fp) {
	// this is for MINA, zcash is using different generator
	xOut.SetOne()
	yOut.Set(&pallasCurveMinaGy)
	zOut.SetOne()
}

func (pallasCurveParams) AddA(out, in *Fp) {
	out.Set(in)
}

func (pallasCurveParams) AddB(out, in *Fp) {
	out.Add(in, &pallasCurveB)
}

// MulByA multiples provided element by 0 (pallas a=0).
func (pallasCurveParams) MulByA(out *Fp, _ *Fp) {
	out.SetZero()
}

// MulBy3B multiples provided element by 15 (pallas b=5, hence 3*5 = 15).
func (pallasCurveParams) MulBy3B(out *Fp, in *Fp) {
	var in2, in4, in8, in16 Fp
	in2.Add(in, in)
	in4.Add(&in2, &in2)
	in8.Add(&in4, &in4)
	in16.Add(&in8, &in8)
	out.Sub(&in16, in)
}

func (pallasCurveMapperParams) MulByA(out, in *Fp) {
	out.Mul(in, &pallasSswuIsogenyA)
}

func (pallasCurveMapperParams) MulByB(out, in *Fp) {
	out.Mul(in, &pallasSswuIsogenyB)
}

func (pallasCurveMapperParams) SetZ(out *Fp) {
	out.Set(&pallasSswuZ)
}

func (pallasCurveMapperParams) SqrtRatio(y, u, v *Fp) (ok uint64) {
	return sswu.SqrtRatio(y, pallasSqrtRatioC1, pallasSqrtRatioC3[:], pallasSqrtRatioC4, pallasSqrtRatioC5, &pallasSqrtRatioC6, &pallasSqrtRatioC7, u, v)
}

func (pallasCurveMapperParams) Sgn0(v *Fp) uint64 {
	return uint64(v.Bytes()[0] & 0b1)
}

func (pallasCurveMapperParams) XNum() []Fp {
	return pallasSswuIsogenyXNum[:]
}

func (pallasCurveMapperParams) XDen() []Fp {
	return pallasSswuIsogenyXDen[:]
}

func (pallasCurveMapperParams) YNum() []Fp {
	return pallasSswuIsogenyYNum[:]
}

func (pallasCurveMapperParams) YDen() []Fp {
	return pallasSswuIsogenyYDen[:]
}
