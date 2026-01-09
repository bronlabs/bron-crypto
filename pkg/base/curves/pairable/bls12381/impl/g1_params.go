package impl

import (
	"crypto/sha256"
	"encoding/binary"

	aimpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
	h2c "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380/mappers/sswu"
)

var (
	_ pointsImpl.ShortWeierstrassCurveParams[*Fp] = g1CurveParams{}
	_ h2c.HasherParams                            = G1CurveHasherParams{}
	_ sswu.ZeroPointMapperParams[*Fp, Fp]         = g1CurveMapperParams{}
	_ h2c.PointMapper[*Fp]                        = g1CurveMapper{}
)

var (
	g1CurveB               Fp
	g1CurveGx              Fp
	g1CurveGy              Fp
	g1CurveMessageExpander = h2c.NewXMDMessageExpander(sha256.New)

	g1SqrtRatioC1  = [...]uint8{0xaa, 0xea, 0xff, 0xff, 0xff, 0xbf, 0x7f, 0xee, 0xff, 0xff, 0x54, 0xac, 0xff, 0xff, 0xaa, 0x07, 0x89, 0x3d, 0xac, 0x3d, 0xa8, 0x34, 0xcc, 0xd9, 0xaf, 0x44, 0xe1, 0x3c, 0xe1, 0xd2, 0x1d, 0xd9, 0x35, 0xeb, 0xd2, 0x90, 0xed, 0xe9, 0xc6, 0x92, 0xa6, 0xf9, 0x5f, 0x8e, 0x7a, 0x44, 0x80, 0x06}
	g1SqrtRationC2 Fp

	g1SswuZ           Fp
	g1SswuIsogenyA    Fp
	g1SswuIsogenyB    Fp
	g1SswuIsogenyXNum [12]Fp
	g1SswuIsogenyXDen [11]Fp
	g1SswuIsogenyYNum [16]Fp
	g1SswuIsogenyYDen [16]Fp
)

//nolint:gochecknoinits // curve params initialization
func init() {
	g1CurveB.MustSetHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004")
	g1CurveGx.MustSetHex("17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb")
	g1CurveGy.MustSetHex("08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1")

	g1SqrtRationC2.MustSetHex("04610e003bd3ac94dfa9246c390d7a78942602029175a4ca366d601f33f3946e3ed39794735c38315d874bc1d70637c3")

	g1SswuZ.MustSetHex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b")
	g1SswuIsogenyA.MustSetHex("00144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d")
	g1SswuIsogenyB.MustSetHex("12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0")
	g1SswuIsogenyXNum[0].MustSetHex("11a05f2b1e833340b809101dd99815856b303e88a2d7005ff2627b56cdb4e2c85610c2d5f2e62d6eaeac1662734649b7")
	g1SswuIsogenyXNum[1].MustSetHex("17294ed3e943ab2f0588bab22147a81c7c17e75b2f6a8417f565e33c70d1e86b4838f2a6f318c356e834eef1b3cb83bb")
	g1SswuIsogenyXNum[2].MustSetHex("0d54005db97678ec1d1048c5d10a9a1bce032473295983e56878e501ec68e25c958c3e3d2a09729fe0179f9dac9edcb0")
	g1SswuIsogenyXNum[3].MustSetHex("1778e7166fcc6db74e0609d307e55412d7f5e4656a8dbf25f1b33289f1b330835336e25ce3107193c5b388641d9b6861")
	g1SswuIsogenyXNum[4].MustSetHex("0e99726a3199f4436642b4b3e4118e5499db995a1257fb3f086eeb65982fac18985a286f301e77c451154ce9ac8895d9")
	g1SswuIsogenyXNum[5].MustSetHex("1630c3250d7313ff01d1201bf7a74ab5db3cb17dd952799b9ed3ab9097e68f90a0870d2dcae73d19cd13c1c66f652983")
	g1SswuIsogenyXNum[6].MustSetHex("0d6ed6553fe44d296a3726c38ae652bfb11586264f0f8ce19008e218f9c86b2a8da25128c1052ecaddd7f225a139ed84")
	g1SswuIsogenyXNum[7].MustSetHex("17b81e7701abdbe2e8743884d1117e53356de5ab275b4db1a682c62ef0f2753339b7c8f8c8f475af9ccb5618e3f0c88e")
	g1SswuIsogenyXNum[8].MustSetHex("080d3cf1f9a78fc47b90b33563be990dc43b756ce79f5574a2c596c928c5d1de4fa295f296b74e956d71986a8497e317")
	g1SswuIsogenyXNum[9].MustSetHex("169b1f8e1bcfa7c42e0c37515d138f22dd2ecb803a0c5c99676314baf4bb1b7fa3190b2edc0327797f241067be390c9e")
	g1SswuIsogenyXNum[10].MustSetHex("10321da079ce07e272d8ec09d2565b0dfa7dccdde6787f96d50af36003b14866f69b771f8c285decca67df3f1605fb7b")
	g1SswuIsogenyXNum[11].MustSetHex("06e08c248e260e70bd1e962381edee3d31d79d7e22c837bc23c0bf1bc24c6b68c24b1b80b64d391fa9c8ba2e8ba2d229")
	g1SswuIsogenyXDen[0].MustSetHex("08ca8d548cff19ae18b2e62f4bd3fa6f01d5ef4ba35b48ba9c9588617fc8ac62b558d681be343df8993cf9fa40d21b1c")
	g1SswuIsogenyXDen[1].MustSetHex("12561a5deb559c4348b4711298e536367041e8ca0cf0800c0126c2588c48bf5713daa8846cb026e9e5c8276ec82b3bff")
	g1SswuIsogenyXDen[2].MustSetHex("0b2962fe57a3225e8137e629bff2991f6f89416f5a718cd1fca64e00b11aceacd6a3d0967c94fedcfcc239ba5cb83e19")
	g1SswuIsogenyXDen[3].MustSetHex("03425581a58ae2fec83aafef7c40eb545b08243f16b1655154cca8abc28d6fd04976d5243eecf5c4130de8938dc62cd8")
	g1SswuIsogenyXDen[4].MustSetHex("13a8e162022914a80a6f1d5f43e7a07dffdfc759a12062bb8d6b44e833b306da9bd29ba81f35781d539d395b3532a21e")
	g1SswuIsogenyXDen[5].MustSetHex("0e7355f8e4e667b955390f7f0506c6e9395735e9ce9cad4d0a43bcef24b8982f7400d24bc4228f11c02df9a29f6304a5")
	g1SswuIsogenyXDen[6].MustSetHex("0772caacf16936190f3e0c63e0596721570f5799af53a1894e2e073062aede9cea73b3538f0de06cec2574496ee84a3a")
	g1SswuIsogenyXDen[7].MustSetHex("14a7ac2a9d64a8b230b3f5b074cf01996e7f63c21bca68a81996e1cdf9822c580fa5b9489d11e2d311f7d99bbdcc5a5e")
	g1SswuIsogenyXDen[8].MustSetHex("0a10ecf6ada54f825e920b3dafc7a3cce07f8d1d7161366b74100da67f39883503826692abba43704776ec3a79a1d641")
	g1SswuIsogenyXDen[9].MustSetHex("095fc13ab9e92ad4476d6e3eb3a56680f682b4ee96f7d03776df533978f31c1593174e4b4b7865002d6384d168ecdd0a")
	g1SswuIsogenyXDen[10].SetOne()
	g1SswuIsogenyYNum[0].MustSetHex("090d97c81ba24ee0259d1f094980dcfa11ad138e48a869522b52af6c956543d3cd0c7aee9b3ba3c2be9845719707bb33")
	g1SswuIsogenyYNum[1].MustSetHex("134996a104ee5811d51036d776fb46831223e96c254f383d0f906343eb67ad34d6c56711962fa8bfe097e75a2e41c696")
	g1SswuIsogenyYNum[2].MustSetHex("00cc786baa966e66f4a384c86a3b49942552e2d658a31ce2c344be4b91400da7d26d521628b00523b8dfe240c72de1f6")
	g1SswuIsogenyYNum[3].MustSetHex("01f86376e8981c217898751ad8746757d42aa7b90eeb791c09e4a3ec03251cf9de405aba9ec61deca6355c77b0e5f4cb")
	g1SswuIsogenyYNum[4].MustSetHex("08cc03fdefe0ff135caf4fe2a21529c4195536fbe3ce50b879833fd221351adc2ee7f8dc099040a841b6daecf2e8fedb")
	g1SswuIsogenyYNum[5].MustSetHex("16603fca40634b6a2211e11db8f0a6a074a7d0d4afadb7bd76505c3d3ad5544e203f6326c95a807299b23ab13633a5f0")
	g1SswuIsogenyYNum[6].MustSetHex("04ab0b9bcfac1bbcb2c977d027796b3ce75bb8ca2be184cb5231413c4d634f3747a87ac2460f415ec961f8855fe9d6f2")
	g1SswuIsogenyYNum[7].MustSetHex("0987c8d5333ab86fde9926bd2ca6c674170a05bfe3bdd81ffd038da6c26c842642f64550fedfe935a15e4ca31870fb29")
	g1SswuIsogenyYNum[8].MustSetHex("09fc4018bd96684be88c9e221e4da1bb8f3abd16679dc26c1e8b6e6a1f20cabe69d65201c78607a360370e577bdba587")
	g1SswuIsogenyYNum[9].MustSetHex("0e1bba7a1186bdb5223abde7ada14a23c42a0ca7915af6fe06985e7ed1e4d43b9b3f7055dd4eba6f2bafaaebca731c30")
	g1SswuIsogenyYNum[10].MustSetHex("19713e47937cd1be0dfd0b8f1d43fb93cd2fcbcb6caf493fd1183e416389e61031bf3a5cce3fbafce813711ad011c132")
	g1SswuIsogenyYNum[11].MustSetHex("18b46a908f36f6deb918c143fed2edcc523559b8aaf0c2462e6bfe7f911f643249d9cdf41b44d606ce07c8a4d0074d8e")
	g1SswuIsogenyYNum[12].MustSetHex("0b182cac101b9399d155096004f53f447aa7b12a3426b08ec02710e807b4633f06c851c1919211f20d4c04f00b971ef8")
	g1SswuIsogenyYNum[13].MustSetHex("0245a394ad1eca9b72fc00ae7be315dc757b3b080d4c158013e6632d3c40659cc6cf90ad1c232a6442d9d3f5db980133")
	g1SswuIsogenyYNum[14].MustSetHex("05c129645e44cf1102a159f748c4a3fc5e673d81d7e86568d9ab0f5d396a7ce46ba1049b6579afb7866b1e715475224b")
	g1SswuIsogenyYNum[15].MustSetHex("15e6be4e990f03ce4ea50b3b42df2eb5cb181d8f84965a3957add4fa95af01b2b665027efec01c7704b456be69c8b604")
	g1SswuIsogenyYDen[0].MustSetHex("16112c4c3a9c98b252181140fad0eae9601a6de578980be6eec3232b5be72e7a07f3688ef60c206d01479253b03663c1")
	g1SswuIsogenyYDen[1].MustSetHex("1962d75c2381201e1a0cbd6c43c348b885c84ff731c4d59ca4a10356f453e01f78a4260763529e3532f6102c2e49a03d")
	g1SswuIsogenyYDen[2].MustSetHex("058df3306640da276faaae7d6e8eb15778c4855551ae7f310c35a5dd279cd2eca6757cd636f96f891e2538b53dbf67f2")
	g1SswuIsogenyYDen[3].MustSetHex("16b7d288798e5395f20d23bf89edb4d1d115c5dbddbcd30e123da489e726af41727364f2c28297ada8d26d98445f5416")
	g1SswuIsogenyYDen[4].MustSetHex("0be0e079545f43e4b00cc912f8228ddcc6d19c9f0f69bbb0542eda0fc9dec916a20b15dc0fd2ededda39142311a5001d")
	g1SswuIsogenyYDen[5].MustSetHex("08d9e5297186db2d9fb266eaac783182b70152c65550d881c5ecd87b6f0f5a6449f38db9dfa9cce202c6477faaf9b7ac")
	g1SswuIsogenyYDen[6].MustSetHex("166007c08a99db2fc3ba8734ace9824b5eecfdfa8d0cf8ef5dd365bc400a0051d5fa9c01a58b1fb93d1a1399126a775c")
	g1SswuIsogenyYDen[7].MustSetHex("16a3ef08be3ea7ea03bcddfabba6ff6ee5a4375efa1f4fd7feb34fd206357132b920f5b00801dee460ee415a15812ed9")
	g1SswuIsogenyYDen[8].MustSetHex("1866c8ed336c61231a1be54fd1d74cc4f9fb0ce4c6af5920abc5750c4bf39b4852cfe2f7bb9248836b233d9d55535d4a")
	g1SswuIsogenyYDen[9].MustSetHex("167a55cda70a6e1cea820597d94a84903216f763e13d87bb5308592e7ea7d4fbc7385ea3d529b35e346ef48bb8913f55")
	g1SswuIsogenyYDen[10].MustSetHex("04d2f259eea405bd48f010a01ad2911d9c6dd039bb61a6290e591b36e636a5c871a5c29f4f83060400f8b49cba8f6aa8")
	g1SswuIsogenyYDen[11].MustSetHex("0accbb67481d033ff5852c1e48c50c477f94ff8aefce42d28c0f9a88cea7913516f968986f7ebbea9684b529e2561092")
	g1SswuIsogenyYDen[12].MustSetHex("0ad6b9514c767fe3c3613144b45f1496543346d98adf02267d5ceef9a00d9b8693000763e3b90ac11e99b138573345cc")
	g1SswuIsogenyYDen[13].MustSetHex("02660400eb2e4f3b628bdd0d53cd76f2bf565b94e72927c1cb748df27942480e420517bd8714cc80d1fadc1326ed06f7")
	g1SswuIsogenyYDen[14].MustSetHex("0e0fa1d816ddc03e6b24255e0d7819c171c40f65e273b853324efcd6356caa205ca2f570f13497804415473a1d634b8f")
	g1SswuIsogenyYDen[15].SetOne()
}

type g1CurveParams struct{}

// G1CurveHasherParams defines hash-to-curve parameters.
type G1CurveHasherParams struct{}
type g1CurveMapperParams struct{}
type g1CurveMapper = sswu.ZeroPointMapper[*Fp, g1CurveMapperParams, Fp]

// AddA adds the curve A parameter to in.
func (g1CurveParams) AddA(out, in *Fp) {
	out.Set(in)
}

// AddB adds the curve B parameter to in.
func (g1CurveParams) AddB(out, in *Fp) {
	out.Add(in, &g1CurveB)
}

// MulByA multiplies by the curve A parameter.
func (g1CurveParams) MulByA(out, _ *Fp) {
	out.SetZero()
}

// MulBy3B where B = 4.
func (g1CurveParams) MulBy3B(out, in *Fp) {
	var b2, b4, b8 Fp
	b2.Add(in, in)
	b4.Add(&b2, &b2)
	b8.Add(&b4, &b4)
	out.Add(&b8, &b4) // b12
}

// ClearCofactor clears the cofactor of the input point.
func (g1CurveParams) ClearCofactor(xOut, yOut, zOut, xIn, yIn, zIn *Fp) {
	var in G1Point
	in.X.Set(xIn)
	in.Y.Set(yIn)
	in.Z.Set(zIn)

	var out G1Point
	aimpl.ScalarMulLowLevel(&out, &in, binary.LittleEndian.AppendUint64(nil, X+1))
	xOut.Set(&out.X)
	yOut.Set(&out.Y)
	zOut.Set(&out.Z)
}

// SetGenerator sets generator coordinates.
func (g1CurveParams) SetGenerator(xOut, yOut, zOut *Fp) {
	xOut.Set(&g1CurveGx)
	yOut.Set(&g1CurveGy)
	zOut.SetOne()
}

// M returns the field extension degree.
func (G1CurveHasherParams) M() uint64 {
	return 1
}

// L returns the hash-to-field length in bytes.
func (G1CurveHasherParams) L() uint64 {
	return 64
}

// MessageExpander returns the RFC 9380 message expander.
func (G1CurveHasherParams) MessageExpander() h2c.MessageExpander {
	return g1CurveMessageExpander
}

// Suite returns the hash-to-curve suite string.
func (G1CurveHasherParams) Suite() []byte {
	return []byte("BLS12381G1_XMD:SHA-256_SSWU_RO_")
}

// MulByA multiplies by the curve A parameter.
func (g1CurveMapperParams) MulByA(out, in *Fp) {
	out.Mul(in, &g1SswuIsogenyA)
}

// MulByB multiplies by the curve B parameter.
func (g1CurveMapperParams) MulByB(out, in *Fp) {
	out.Mul(in, &g1SswuIsogenyB)
}

// SetZ sets the SSWU Z parameter.
func (g1CurveMapperParams) SetZ(out *Fp) {
	out.Set(&g1SswuZ)
}

// SqrtRatio computes sqrt(u/v) with curve-specific parameters.
func (g1CurveMapperParams) SqrtRatio(out, u, v *Fp) (ok ct.Bool) {
	return sswu.SqrtRatio3Mod4(out, g1SqrtRatioC1[:], &g1SqrtRationC2, u, v)
}

// Sgn0 returns the sign bit per RFC 9380.
func (g1CurveMapperParams) Sgn0(v *Fp) ct.Bool {
	return ct.Bool(uint64(v.Bytes()[0] & 0b1))
}

// XNum returns isogeny x numerator coefficients.
func (g1CurveMapperParams) XNum() []Fp {
	return g1SswuIsogenyXNum[:]
}

// XDen returns isogeny x denominator coefficients.
func (g1CurveMapperParams) XDen() []Fp {
	return g1SswuIsogenyXDen[:]
}

// YNum returns isogeny y numerator coefficients.
func (g1CurveMapperParams) YNum() []Fp {
	return g1SswuIsogenyYNum[:]
}

// YDen returns isogeny y denominator coefficients.
func (g1CurveMapperParams) YDen() []Fp {
	return g1SswuIsogenyYDen[:]
}
