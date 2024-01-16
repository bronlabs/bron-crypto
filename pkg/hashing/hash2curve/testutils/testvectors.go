package testutils

import (
	"bytes"
	"strings"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curve25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	hashing "github.com/copperexchange/krypton-primitives/pkg/hashing/hash2curve"
)

// TestVector implements the test vectors for hash to curve, as specified in
// https://datatracker.ietf.org/doc/html/rfc9380#appendix-J
type TestVector struct {
	SuiteName string
	Dst       string
	TestCases []TestCase
}

type TestCase struct {
	Msg  string
	Px   string
	Py   string
	U0   string
	U1   string
	Q0x  string
	Q0y  string
	Q1x  string
	Q1y  string
	PxI  string
	PyI  string
	U0I  string
	U1I  string
	Q0xI string
	Q0yI string
	Q1xI string
	Q1yI string
}

func MakeCurveHasher(curve curves.Curve, tv *TestVector) (hashing.CurveHasher, error) {
	appTag, found := strings.CutSuffix(tv.Dst, tv.SuiteName)
	if !found {
		return nil, errs.NewVerificationFailed("could not cut suffix from dst")
	}
	suiteIdSections := strings.Split(tv.SuiteName, hashing.DST_ID_SEPARATOR)
	if len(suiteIdSections) != 5 || suiteIdSections[0] != curve.Name() || suiteIdSections[3] != hashing.DST_ENC_VAR {
		return nil, errs.NewVerificationFailed("invalid dst")
	}
	mapperTag := suiteIdSections[2]
	var ch hashing.CurveHasher
	switch hasherNCurveTag := suiteIdSections[1]; {
	case strings.Contains(hasherNCurveTag, hashing.DST_TAG_SHA256):
		ch = hashing.NewCurveHasherSha256(curve, appTag, mapperTag)
	case strings.Contains(hasherNCurveTag, hashing.DST_TAG_SHA512):
		ch = hashing.NewCurveHasherSha512(curve, appTag, mapperTag)
	case strings.Contains(hasherNCurveTag, hashing.DST_TAG_SHAKE256):
		ch = hashing.NewShake256Hasher(curve, appTag, mapperTag)
	default:
		return nil, errs.NewVerificationFailed("unsupported hasher")
	}
	if !bytes.Equal(ch.Dst(), []byte(tv.Dst)) {
		return nil, errs.NewVerificationFailed("dst mismatch")
	}
	return ch, nil
}

func SetCurveHasher(curve curves.Curve, ch hashing.CurveHasher) curves.Curve {
	switch curve.Name() {
	case p256.NewCurve().Name():
		c := p256.NewCurve()
		c.CurveHasher = ch
		return c
	case edwards25519.NewCurve().Name():
		c := edwards25519.NewCurve()
		c.CurveHasher = ch
		return c
	case k256.NewCurve().Name():
		c := k256.NewCurve()
		c.CurveHasher = ch
		return c
	case curve25519.NewCurve().Name():
		c := edwards25519.NewCurve()
		c.CurveHasher = ch
		return c
	case bls12381.NewG1().Name():
		c := bls12381.NewG1()
		c.CurveHasher = ch
		return c
	case bls12381.NewG2().Name():
		c := bls12381.NewG2()
		c.CurveHasher = ch
		return c
	default:
		panic("unsupported curve")
	}
}

func NewHash2CurveTestVector(curve curves.Curve) *TestVector {
	switch curve.Name() {
	case p256.NewCurve().Name():
		return P256_TestVector
	case edwards25519.NewCurve().Name():
		return Edwards25519_TestVector
	case k256.NewCurve().Name():
		return Secp256k1_TestVector
	case curve25519.NewCurve().Name():
		return Curve25519_TestVector
	case bls12381.NewG1().Name():
		return BLS12381G1_TestVector
	case bls12381.NewG2().Name():
		return BLS12381G2_TestVector
	default:
		panic("unsupported curve")
	}
}

// RFC 9380 Appendix J.1.1. P256_XMD:SHA-256_SSWU_RO_
var P256_TestVector = &TestVector{
	SuiteName: "P256_XMD:SHA-256_SSWU_RO_",
	Dst:       "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_",
	TestCases: []TestCase{{
		Msg: "",
		Px:  "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
		Py:  "8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415",
		U0:  "ad5342c66a6dd0ff080df1da0ea1c04b96e0330dd89406465eeba11582515009",
		U1:  "8c0f1d43204bd6f6ea70ae8013070a1518b43873bcd850aafa0a9e220e2eea5a",
		Q0x: "ab640a12220d3ff283510ff3f4b1953d09fad35795140b1c5d64f313967934d5",
		Q0y: "dccb558863804a881d4fff3455716c836cef230e5209594ddd33d85c565b19b1",
		Q1x: "51cce63c50d972a6e51c61334f0f4875c9ac1cd2d3238412f84e31da7d980ef5",
		Q1y: "b45d1a36d00ad90e5ec7840a60a4de411917fbe7c82c3949a6e699e5a1b66aac",
	}, {
		Msg: "abc",
		Px:  "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
		Py:  "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e",
		U0:  "afe47f2ea2b10465cc26ac403194dfb68b7f5ee865cda61e9f3e07a537220af1",
		U1:  "379a27833b0bfe6f7bdca08e1e83c760bf9a338ab335542704edcd69ce9e46e0",
		Q0x: "5219ad0ddef3cc49b714145e91b2f7de6ce0a7a7dc7406c7726c7e373c58cb48",
		Q0y: "7950144e52d30acbec7b624c203b1996c99617d0b61c2442354301b191d93ecf",
		Q1x: "019b7cb4efcfeaf39f738fe638e31d375ad6837f58a852d032ff60c69ee3875f",
		Q1y: "589a62d2b22357fed5449bc38065b760095ebe6aeac84b01156ee4252715446e",
	}, {
		Msg: "abcdef0123456789",
		Px:  "65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
		Py:  "cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3",
		U0:  "0fad9d125a9477d55cf9357105b0eb3a5c4259809bf87180aa01d651f53d312c",
		U1:  "b68597377392cd3419d8fcc7d7660948c8403b19ea78bbca4b133c9d2196c0fb",
		Q0x: "a17bdf2965eb88074bc01157e644ed409dac97cfcf0c61c998ed0fa45e79e4a2",
		Q0y: "4f1bc80c70d411a3cc1d67aeae6e726f0f311639fee560c7f5a664554e3c9c2e",
		Q1x: "7da48bb67225c1a17d452c983798113f47e438e4202219dd0715f8419b274d66",
		Q1y: "b765696b2913e36db3016c47edb99e24b1da30e761a8a3215dc0ec4d8f96e6f9",
	}, {
		Msg: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" +
			"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" +
			"qqqqq",
		Px:  "4be61ee205094282ba8a2042bcb48d88dfbb609301c49aa8b078533dc65a0b5d",
		Py:  "98f8df449a072c4721d241a3b1236d3caccba603f916ca680f4539d2bfb3c29e",
		U0:  "3bbc30446f39a7befad080f4d5f32ed116b9534626993d2cc5033f6f8d805919",
		U1:  "76bb02db019ca9d3c1e02f0c17f8baf617bbdae5c393a81d9ce11e3be1bf1d33",
		Q0x: "c76aaa823aeadeb3f356909cb08f97eee46ecb157c1f56699b5efebddf0e6398",
		Q0y: "776a6f45f528a0e8d289a4be12c4fab80762386ec644abf2bffb9b627e4352b1",
		Q1x: "418ac3d85a5ccc4ea8dec14f750a3a9ec8b85176c95a7022f391826794eb5a75",
		Q1y: "fd6604f69e9d9d2b74b072d14ea13050db72c932815523305cb9e807cc900aff",
	}, {
		Msg: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaa",
		Px:  "457ae2981f70ca85d8e24c308b14db22f3e3862c5ea0f652ca38b5e49cd64bc5",
		Py:  "ecb9f0eadc9aeed232dabc53235368c1394c78de05dd96893eefa62b0f4757dc",
		U0:  "4ebc95a6e839b1ae3c63b847798e85cb3c12d3817ec6ebc10af6ee51adb29fec",
		U1:  "4e21af88e22ea80156aff790750121035b3eefaa96b425a8716e0d20b4e269ee",
		Q0x: "d88b989ee9d1295df413d4456c5c850b8b2fb0f5402cc5c4c7e815412e926db8",
		Q0y: "bb4a1edeff506cf16def96afff41b16fc74f6dbd55c2210e5b8f011ba32f4f40",
		Q1x: "a281e34e628f3a4d2a53fa87ff973537d68ad4fbc28d3be5e8d9f6a2571c5a4b",
		Q1y: "f6ed88a7aab56a488100e6f1174fa9810b47db13e86be999644922961206e184",
	}},
}

// RFC 9380 Appendix J.4.1. curve25519_XMD:SHA-512_ELL2_RO_
var Curve25519_TestVector = &TestVector{
	SuiteName: "curve25519_XMD:SHA-512_ELL2_RO_",
	Dst:       "QUUX-V01-CS02-with-curve25519_XMD:SHA-512_ELL2_RO_",
	TestCases: []TestCase{{
		Msg: "",
		Px:  "2de3780abb67e861289f5749d16d3e217ffa722192d16bbd9d1bfb9d112b98c0",
		Py:  "3b5dc2a498941a1033d176567d457845637554a2fe7a3507d21abd1c1bd6e878",
		U0:  "005fe8a7b8fef0a16c105e6cadf5a6740b3365e18692a9c05bfbb4d97f645a6a",
		U1:  "1347edbec6a2b5d8c02e058819819bee177077c9d10a4ce165aab0fd0252261a",
		Q0x: "36b4df0c864c64707cbf6cf36e9ee2c09a6cb93b28313c169be29561bb904f98",
		Q0y: "6cd59d664fb58c66c892883cd0eb792e52055284dac3907dd756b45d15c3983d",
		Q1x: "3fa114783a505c0b2b2fbeef0102853c0b494e7757f2a089d0daae7ed9a0db2b",
		Q1y: "76c0fe7fec932aaafb8eefb42d9cbb32eb931158f469ff3050af15cfdbbeff94",
	}, {
		Msg: "abc",
		Px:  "2b4419f1f2d48f5872de692b0aca72cc7b0a60915dd70bde432e826b6abc526d",
		Py:  "1b8235f255a268f0a6fa8763e97eb3d22d149343d495da1160eff9703f2d07dd",
		U0:  "49bed021c7a3748f09fa8cdfcac044089f7829d3531066ac9e74e0994e05bc7d",
		U1:  "5c36525b663e63389d886105cee7ed712325d5a97e60e140aba7e2ce5ae851b6",
		Q0x: "16b3d86e056b7970fa00165f6f48d90b619ad618791661b7b5e1ec78be10eac1",
		Q0y: "4ab256422d84c5120b278cbdfc4e1facc5baadffeccecf8ee9bf3946106d50ca",
		Q1x: "7ec29ddbf34539c40adfa98fcb39ec36368f47f30e8f888cc7e86f4d46e0c264",
		Q1y: "10d1abc1cae2d34c06e247f2141ba897657fb39f1080d54f09ce0af128067c74",
	}, {
		Msg: "abcdef0123456789",
		Px:  "68ca1ea5a6acf4e9956daa101709b1eee6c1bb0df1de3b90d4602382a104c036",
		Py:  "2a375b656207123d10766e68b938b1812a4a6625ff83cb8d5e86f58a4be08353",
		U0:  "6412b7485ba26d3d1b6c290a8e1435b2959f03721874939b21782df17323d160",
		U1:  "24c7b46c1c6d9a21d32f5707be1380ab82db1054fde82865d5c9e3d968f287b2",
		Q0x: "71de3dadfe268872326c35ac512164850860567aea0e7325e6b91a98f86533ad",
		Q0y: "26a08b6e9a18084c56f2147bf515414b9b63f1522e1b6c5649f7d4b0324296ec",
		Q1x: "5704069021f61e41779e2ba6b932268316d6d2a6f064f997a22fef16d1eaeaca",
		Q1y: "50483c7540f64fb4497619c050f2c7fe55454ec0f0e79870bb44302e34232210",
	}, {
		Msg: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" +
			"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" +
			"qqqqq",
		Px:  "096e9c8bae6c06b554c1ee69383bb0e82267e064236b3a30608d4ed20b73ac5a",
		Py:  "1eb5a62612cafb32b16c3329794645b5b948d9f8ffe501d4e26b073fef6de355",
		U0:  "5e123990f11bbb5586613ffabdb58d47f64bb5f2fa115f8ea8df0188e0c9e1b5",
		U1:  "5e8553eb00438a0bb1e7faa59dec6d8087f9c8011e5fb8ed9df31cb6c0d4ac19",
		Q0x: "7a94d45a198fb5daa381f45f2619ab279744efdd8bd8ed587fc5b65d6cea1df0",
		Q0y: "67d44f85d376e64bb7d713585230cdbfafc8e2676f7568e0b6ee59361116a6e1",
		Q1x: "30506fb7a32136694abd61b6113770270debe593027a968a01f271e146e60c18",
		Q1y: "7eeee0e706b40c6b5174e551426a67f975ad5a977ee2f01e8e20a6d612458c3b",
	}, {
		Msg: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaa",
		Px:  "1bc61845a138e912f047b5e70ba9606ba2a447a4dade024c8ef3dd42b7bbc5fe",
		Py:  "623d05e47b70e25f7f1d51dda6d7c23c9a18ce015fe3548df596ea9e38c69bf1",
		U0:  "20f481e85da7a3bf60ac0fb11ed1d0558fc6f941b3ac5469aa8b56ec883d6d7d",
		U1:  "017d57fd257e9a78913999a23b52ca988157a81b09c5442501d07fed20869465",
		Q0x: "02d606e2699b918ee36f2818f2bc5013e437e673c9f9b9cdc15fd0c5ee913970",
		Q0y: "29e9dc92297231ef211245db9e31767996c5625dfbf92e1c8107ef887365de1e",
		Q1x: "38920e9b988d1ab7449c0fa9a6058192c0c797bb3d42ac345724341a1aa98745",
		Q1y: "24dcc1be7c4d591d307e89049fd2ed30aae8911245a9d8554bf6032e5aa40d3d",
	}},
}

// RFC 9380 Appendix J.5.1. edwards25519_XMD:SHA-512_ELL2_RO_
var Edwards25519_TestVector = &TestVector{
	SuiteName: "edwards25519_XMD:SHA-512_ELL2_RO_",
	Dst:       "QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_RO_",
	TestCases: []TestCase{{
		Msg: "",
		Px:  "3c3da6925a3c3c268448dcabb47ccde5439559d9599646a8260e47b1e4822fc6",
		Py:  "09a6c8561a0b22bef63124c588ce4c62ea83a3c899763af26d795302e115dc21",
		U0:  "03fef4813c8cb5f98c6eef88fae174e6e7d5380de2b007799ac7ee712d203f3a",
		U1:  "780bdddd137290c8f589dc687795aafae35f6b674668d92bf92ae793e6a60c75",
		Q0x: "6549118f65bb617b9e8b438decedc73c496eaed496806d3b2eb9ee60b88e09a7",
		Q0y: "7315bcc8cf47ed68048d22bad602c6680b3382a08c7c5d3f439a973fb4cf9feb",
		Q1x: "31dcfc5c58aa1bee6e760bf78cbe71c2bead8cebb2e397ece0f37a3da19c9ed2",
		Q1y: "7876d81474828d8a5928b50c82420b2bd0898d819e9550c5c82c39fc9bafa196",
	}, {
		Msg: "abc",
		Px:  "608040b42285cc0d72cbb3985c6b04c935370c7361f4b7fbdb1ae7f8c1a8ecad",
		Py:  "1a8395b88338f22e435bbd301183e7f20a5f9de643f11882fb237f88268a5531",
		U0:  "5081955c4141e4e7d02ec0e36becffaa1934df4d7a270f70679c78f9bd57c227",
		U1:  "005bdc17a9b378b6272573a31b04361f21c371b256252ae5463119aa0b925b76",
		Q0x: "5c1525bd5d4b4e034512949d187c39d48e8cd84242aa4758956e4adc7d445573",
		Q0y: "2bf426cf7122d1a90abc7f2d108befc2ef415ce8c2d09695a7407240faa01f29",
		Q1x: "37b03bba828860c6b459ddad476c83e0f9285787a269df2156219b7e5c86210c",
		Q1y: "285ebf5412f84d0ad7bb4e136729a9ffd2195d5b8e73c0dc85110ce06958f432",
	}, {
		Msg: "abcdef0123456789",
		Px:  "6d7fabf47a2dc03fe7d47f7dddd21082c5fb8f86743cd020f3fb147d57161472",
		Py:  "53060a3d140e7fbcda641ed3cf42c88a75411e648a1add71217f70ea8ec561a6",
		U0:  "285ebaa3be701b79871bcb6e225ecc9b0b32dff2d60424b4c50642636a78d5b3",
		U1:  "2e253e6a0ef658fedb8e4bd6a62d1544fd6547922acb3598ec6b369760b81b31",
		Q0x: "3ac463dd7fddb773b069c5b2b01c0f6b340638f54ee3bd92d452fcec3015b52d",
		Q0y: "7b03ba1e8db9ec0b390d5c90168a6a0b7107156c994c674b61fe696cbeb46baf",
		Q1x: "0757e7e904f5e86d2d2f4acf7e01c63827fde2d363985aa7432106f1b3a444ec",
		Q1y: "50026c96930a24961e9d86aa91ea1465398ff8e42015e2ec1fa397d416f6a1c0",
	}, {
		Msg: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" +
			"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" +
			"qqqqq",
		Px:  "5fb0b92acedd16f3bcb0ef83f5c7b7a9466b5f1e0d8d217421878ea3686f8524",
		Py:  "2eca15e355fcfa39d2982f67ddb0eea138e2994f5956ed37b7f72eea5e89d2f7",
		U0:  "4fedd25431c41f2a606952e2945ef5e3ac905a42cf64b8b4d4a83c533bf321af",
		U1:  "02f20716a5801b843987097a8276b6d869295b2e11253751ca72c109d37485a9",
		Q0x: "703e69787ea7524541933edf41f94010a201cc841c1cce60205ec38513458872",
		Q0y: "32bb192c4f89106466f0874f5fd56a0d6b6f101cb714777983336c159a9bec75",
		Q1x: "0c9077c5c31720ed9413abe59bf49ce768506128d810cb882435aa90f713ef6b",
		Q1y: "7d5aec5210db638c53f050597964b74d6dda4be5b54fa73041bf909ccb3826cb",
	}, {
		Msg: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaa",
		Px:  "0efcfde5898a839b00997fbe40d2ebe950bc81181afbd5cd6b9618aa336c1e8c",
		Py:  "6dc2fc04f266c5c27f236a80b14f92ccd051ef1ff027f26a07f8c0f327d8f995",
		U0:  "6e34e04a5106e9bd59f64aba49601bf09d23b27f7b594e56d5de06df4a4ea33b",
		U1:  "1c1c2cb59fc053f44b86c5d5eb8c1954b64976d0302d3729ff66e84068f5fd96",
		Q0x: "21091b2e3f9258c7dfa075e7ae513325a94a3d8a28e1b1cb3b5b6f5d65675592",
		Q0y: "41a33d324c89f570e0682cdf7bdb78852295daf8084c669f2cc9692896ab5026",
		Q1x: "4c07ec48c373e39a23bd7954f9e9b66eeab9e5ee1279b867b3d5315aa815454f",
		Q1y: "67ccac7c3cb8d1381242d8d6585c57eabaddbb5dca5243a68a8aeb5477d94b3a",
	}},
}

// RFC 9380 Appendix J.8.1. secp256k1_XMD:SHA-256_SSWU_RO_
var Secp256k1_TestVector = &TestVector{
	SuiteName: "secp256k1_XMD:SHA-256_SSWU_RO_",
	Dst:       "QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_",
	TestCases: []TestCase{{
		Msg: "",
		Px:  "c1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb1346",
		Py:  "64fa678e07ae116126f08b022a94af6de15985c996c3a91b64c406a960e51067",
		U0:  "6b0f9910dd2ba71c78f2ee9f04d73b5f4c5f7fc773a701abea1e573cab002fb3",
		U1:  "1ae6c212e08fe1a5937f6202f929a2cc8ef4ee5b9782db68b0d5799fd8f09e16",
		Q0x: "74519ef88b32b425a095e4ebcc84d81b64e9e2c2675340a720bb1a1857b99f1e",
		Q0y: "c174fa322ab7c192e11748beed45b508e9fdb1ce046dee9c2cd3a2a86b410936",
		Q1x: "44548adb1b399263ded3510554d28b4bead34b8cf9a37b4bd0bd2ba4db87ae63",
		Q1y: "96eb8e2faf05e368efe5957c6167001760233e6dd2487516b46ae725c4cce0c6",
	}, {
		Msg: "abc",
		Px:  "3377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb2c4b",
		Py:  "7f95890f33efebd1044d382a01b1bee0900fb6116f94688d487c6c7b9c8371f6",
		U0:  "128aab5d3679a1f7601e3bdf94ced1f43e491f544767e18a4873f397b08a2b61",
		U1:  "5897b65da3b595a813d0fdcc75c895dc531be76a03518b044daaa0f2e4689e00",
		Q0x: "07dd9432d426845fb19857d1b3a91722436604ccbbbadad8523b8fc38a5322d7",
		Q0y: "604588ef5138cffe3277bbd590b8550bcbe0e523bbaf1bed4014a467122eb33f",
		Q1x: "e9ef9794d15d4e77dde751e06c182782046b8dac05f8491eb88764fc65321f78",
		Q1y: "cb07ce53670d5314bf236ee2c871455c562dd76314aa41f012919fe8e7f717b3",
	}, {
		Msg: "abcdef0123456789",
		Px:  "bac54083f293f1fe08e4a70137260aa90783a5cb84d3f35848b324d0674b0e3a",
		Py:  "4436476085d4c3c4508b60fcf4389c40176adce756b398bdee27bca19758d828",
		U0:  "ea67a7c02f2cd5d8b87715c169d055a22520f74daeb080e6180958380e2f98b9",
		U1:  "7434d0d1a500d38380d1f9615c021857ac8d546925f5f2355319d823a478da18",
		Q0x: "576d43ab0260275adf11af990d130a5752704f79478628761720808862544b5d",
		Q0y: "643c4a7fb68ae6cff55edd66b809087434bbaff0c07f3f9ec4d49bb3c16623c3",
		Q1x: "f89d6d261a5e00fe5cf45e827b507643e67c2a947a20fd9ad71039f8b0e29ff8",
		Q1y: "b33855e0cc34a9176ead91c6c3acb1aacb1ce936d563bc1cee1dcffc806caf57",
	}, {
		Msg: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" +
			"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" +
			"qqqqq",
		Px:  "e2167bc785333a37aa562f021f1e881defb853839babf52a7f72b102e41890e9",
		Py:  "f2401dd95cc35867ffed4f367cd564763719fbc6a53e969fb8496a1e6685d873",
		U0:  "eda89a5024fac0a8207a87e8cc4e85aa3bce10745d501a30deb87341b05bcdf5",
		U1:  "dfe78cd116818fc2c16f3837fedbe2639fab012c407eac9dfe9245bf650ac51d",
		Q0x: "9c91513ccfe9520c9c645588dff5f9b4e92eaf6ad4ab6f1cd720d192eb58247a",
		Q0y: "c7371dcd0134412f221e386f8d68f49e7fa36f9037676e163d4a063fbf8a1fb8",
		Q1x: "10fee3284d7be6bd5912503b972fc52bf4761f47141a0015f1c6ae36848d869b",
		Q1y: "0b163d9b4bf21887364332be3eff3c870fa053cf508732900fc69a6eb0e1b672",
	}, {
		Msg: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaa",
		Px:  "e3c8d35aaaf0b9b647e88a0a0a7ee5d5bed5ad38238152e4e6fd8c1f8cb7c998",
		Py:  "8446eeb6181bf12f56a9d24e262221cc2f0c4725c7e3803024b5888ee5823aa6",
		U0:  "8d862e7e7e23d7843fe16d811d46d7e6480127a6b78838c277bca17df6900e9f",
		U1:  "68071d2530f040f081ba818d3c7188a94c900586761e9115efa47ae9bd847938",
		Q0x: "b32b0ab55977b936f1e93fdc68cec775e13245e161dbfe556bbb1f72799b4181",
		Q0y: "2f5317098360b722f132d7156a94822641b615c91f8663be69169870a12af9e8",
		Q1x: "148f98780f19388b9fa93e7dc567b5a673e5fca7079cd9cdafd71982ec4c5e12",
		Q1y: "3989645d83a433bc0c001f3dac29af861f33a6fd1e04f4b36873f5bff497298a",
	}},
}

// RFC 9380 Appendix J.9.1. BLS12381G1_XMD:SHA-256_SSWU_RO_
var BLS12381G1_TestVector = &TestVector{
	SuiteName: "BLS12381G1_XMD:SHA-256_SSWU_RO_",
	Dst:       "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_",
	TestCases: []TestCase{{
		Msg: "",
		Px:  "052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1",
		Py:  "08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265",
		U0:  "0ba14bd907ad64a016293ee7c2d276b8eae71f25a4b941eece7b0d89f17f75cb3ae5438a614fb61d6835ad59f29c564f",
		U1:  "019b9bd7979f12657976de2884c7cce192b82c177c80e0ec604436a7f538d231552f0d96d9f7babe5fa3b19b3ff25ac9",
		Q0x: "11a3cce7e1d90975990066b2f2643b9540fa40d6137780df4e753a8054d07580db3b7f1f03396333d4a359d1fe3766fe",
		Q0y: "0eeaf6d794e479e270da10fdaf768db4c96b650a74518fc67b04b03927754bac66f3ac720404f339ecdcc028afa091b7",
		Q1x: "160003aaf1632b13396dbad518effa00fff532f604de1a7fc2082ff4cb0afa2d63b2c32da1bef2bf6c5ca62dc6b72f9c",
		Q1y: "0d8bb2d14e20cf9f6036152ed386d79189415b6d015a20133acb4e019139b94e9c146aaad5817f866c95d609a361735e",
	}, {
		Msg: "abc",
		Px:  "03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903",
		Py:  "0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d",
		U0:  "0d921c33f2bad966478a03ca35d05719bdf92d347557ea166e5bba579eea9b83e9afa5c088573c2281410369fbd32951",
		U1:  "003574a00b109ada2f26a37a91f9d1e740dffd8d69ec0c35e1e9f4652c7dba61123e9dd2e76c655d956e2b3462611139",
		Q0x: "125435adce8e1cbd1c803e7123f45392dc6e326d292499c2c45c5865985fd74fe8f042ecdeeec5ecac80680d04317d80",
		Q0y: "0e8828948c989126595ee30e4f7c931cbd6f4570735624fd25aef2fa41d3f79cfb4b4ee7b7e55a8ce013af2a5ba20bf2",
		Q1x: "11def93719829ecda3b46aa8c31fc3ac9c34b428982b898369608e4f042babee6c77ab9218aad5c87ba785481eff8ae4",
		Q1y: "0007c9cef122ccf2efd233d6eb9bfc680aa276652b0661f4f820a653cec1db7ff69899f8e52b8e92b025a12c822a6ce6",
	}, {
		Msg: "abcdef0123456789",
		Px:  "11e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf268c263ddd57a6a27200a784cbc248e84f357ce82d98",
		Py:  "03a87ae2caf14e8ee52e51fa2ed8eefe80f02457004ba4d486d6aa1f517c0889501dc7413753f9599b099ebcbbd2d709",
		U0:  "062d1865eb80ebfa73dcfc45db1ad4266b9f3a93219976a3790ab8d52d3e5f1e62f3b01795e36834b17b70e7b76246d4",
		U1:  "0cdc3e2f271f29c4ff75020857ce6c5d36008c9b48385ea2f2bf6f96f428a3deb798aa033cd482d1cdc8b30178b08e3a",
		Q0x: "08834484878c217682f6d09a4b51444802fdba3d7f2df9903a0ddadb92130ebbfa807fffa0eabf257d7b48272410afff",
		Q0y: "0b318f7ecf77f45a0f038e62d7098221d2dbbca2a394164e2e3fe953dc714ac2cde412d8f2d7f0c03b259e6795a2508e",
		Q1x: "158418ed6b27e2549f05531a8281b5822b31c3bf3144277fbb977f8d6e2694fedceb7011b3c2b192f23e2a44b2bd106e",
		Q1y: "1879074f344471fac5f839e2b4920789643c075792bec5af4282c73f7941cda5aa77b00085eb10e206171b9787c4169f",
	}, {
		Msg: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" +
			"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
		Px:  "15f68eaa693b95ccb85215dc65fa81038d69629f70aeee0d0f677cf22285e7bf58d7cb86eefe8f2e9bc3f8cb84fac488",
		Py:  "1807a1d50c29f430b8cafc4f8638dfeeadf51211e1602a5f184443076715f91bb90a48ba1e370edce6ae1062f5e6dd38",
		U0:  "010476f6a060453c0b1ad0b628f3e57c23039ee16eea5e71bb87c3b5419b1255dc0e5883322e563b84a29543823c0e86",
		U1:  "0b1a912064fb0554b180e07af7e787f1f883a0470759c03c1b6509eb8ce980d1670305ae7b928226bb58fdc0a419f46e",
		Q0x: "0cbd7f84ad2c99643fea7a7ac8f52d63d66cefa06d9a56148e58b984b3dd25e1f41ff47154543343949c64f88d48a710",
		Q0y: "052c00e4ed52d000d94881a5638ae9274d3efc8bc77bc0e5c650de04a000b2c334a9e80b85282a00f3148dfdface0865",
		Q1x: "06493fb68f0d513af08be0372f849436a787e7b701ae31cb964d968021d6ba6bd7d26a38aaa5a68e8c21a6b17dc8b579",
		Q1y: "02e98f2ccf5802b05ffaac7c20018bc0c0b2fd580216c4aa2275d2909dc0c92d0d0bdc979226adeb57a29933536b6bb4",
	}, {
		Msg: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Px:  "082aabae8b7dedb0e78aeb619ad3bfd9277a2f77ba7fad20ef6aabdc6c31d19ba5a6d12283553294c1825c4b3ca2dcfe",
		Py:  "05b84ae5a942248eea39e1d91030458c40153f3b654ab7872d779ad1e942856a20c438e8d99bc8abfbf74729ce1f7ac8",
		U0:  "0a8ffa7447f6be1c5a2ea4b959c9454b431e29ccc0802bc052413a9c5b4f9aac67a93431bd480d15be1e057c8a08e8c6",
		U1:  "05d487032f602c90fa7625dbafe0f4a49ef4a6b0b33d7bb349ff4cf5410d297fd6241876e3e77b651cfc8191e40a68b7",
		Q0x: "0cf97e6dbd0947857f3e578231d07b309c622ade08f2c08b32ff372bd90db19467b2563cc997d4407968d4ac80e154f8",
		Q0y: "127f0cddf2613058101a5701f4cb9d0861fd6c2a1b8e0afe194fccf586a3201a53874a2761a9ab6d7220c68661a35ab3",
		Q1x: "092f1acfa62b05f95884c6791fba989bbe58044ee6355d100973bf9553ade52b47929264e6ae770fb264582d8dce512a",
		Q1y: "028e6d0169a72cfedb737be45db6c401d3adfb12c58c619c82b93a5dfcccef12290de530b0480575ddc8397cda0bbebf",
	}},
}

// RFC 9380 Appendix J.10.1. BLS12381G2_XMD:SHA-256_SSWU_RO_
var BLS12381G2_TestVector = &TestVector{
	SuiteName: "BLS12381G2_XMD:SHA-256_SSWU_RO_",
	Dst:       "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_",
	TestCases: []TestCase{{
		Msg:  "",
		Px:   "0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a",
		PxI:  "05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d",
		Py:   "0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92",
		PyI:  "12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6",
		U0:   "03dbc2cce174e91ba93cbb08f26b917f98194a2ea08d1cce75b2b9cc9f21689d80bd79b594a613d0a68eb807dfdc1cf8",
		U0I:  "05a2acec64114845711a54199ea339abd125ba38253b70a92c876df10598bd1986b739cad67961eb94f7076511b3b39a",
		U1:   "02f99798e8a5acdeed60d7e18e9120521ba1f47ec090984662846bc825de191b5b7641148c0dbc237726a334473eee94",
		U1I:  "145a81e418d4010cc027a68f14391b30074e89e60ee7a22f87217b2f6eb0c4b94c9115b436e6fa4607e95a98de30a435",
		Q0x:  "019ad3fc9c72425a998d7ab1ea0e646a1f6093444fc6965f1cad5a3195a7b1e099c050d57f45e3fa191cc6d75ed7458c",
		Q0xI: "171c88b0b0efb5eb2b88913a9e74fe111a4f68867b59db252ce5868af4d1254bfab77ebde5d61cd1a86fb2fe4a5a1c1d",
		Q0y:  "0ba10604e62bdd9eeeb4156652066167b72c8d743b050fb4c1016c31b505129374f76e03fa127d6a156213576910fef3",
		Q0yI: "0eb22c7a543d3d376e9716a49b72e79a89c9bfe9feee8533ed931cbb5373dde1fbcd7411d8052e02693654f71e15410a",
		Q1x:  "113d2b9cd4bd98aee53470b27abc658d91b47a78a51584f3d4b950677cfb8a3e99c24222c406128c91296ef6b45608be",
		Q1xI: "13855912321c5cb793e9d1e88f6f8d342d49c0b0dbac613ee9e17e3c0b3c97dfbb5a49cc3fb45102fdbaf65e0efe2632",
		Q1y:  "0fd3def0b7574a1d801be44fde617162aa2e89da47f464317d9bb5abc3a7071763ce74180883ad7ad9a723a9afafcdca",
		Q1yI: "056f617902b3c0d0f78a9a8cbda43a26b65f602f8786540b9469b060db7b38417915b413ca65f875c130bebfaa59790c",
	}, {
		Msg:  "abc",
		Px:   "02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6",
		PxI:  "139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8",
		Py:   "1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48",
		PyI:  "00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16",
		U0:   "15f7c0aa8f6b296ab5ff9c2c7581ade64f4ee6f1bf18f55179ff44a2cf355fa53dd2a2158c5ecb17d7c52f63e7195771",
		U0I:  "01c8067bf4c0ba709aa8b9abc3d1cef589a4758e09ef53732d670fd8739a7274e111ba2fcaa71b3d33df2a3a0c8529dd",
		U1:   "187111d5e088b6b9acfdfad078c4dacf72dcd17ca17c82be35e79f8c372a693f60a033b461d81b025864a0ad051a06e4",
		U1I:  "08b852331c96ed983e497ebc6dee9b75e373d923b729194af8e72a051ea586f3538a6ebb1e80881a082fa2b24df9f566",
		Q0x:  "12b2e525281b5f4d2276954e84ac4f42cf4e13b6ac4228624e17760faf94ce5706d53f0ca1952f1c5ef75239aeed55ad",
		Q0xI: "05d8a724db78e570e34100c0bc4a5fa84ad5839359b40398151f37cff5a51de945c563463c9efbdda569850ee5a53e77",
		Q0y:  "02eacdc556d0bdb5d18d22f23dcb086dd106cad713777c7e6407943edbe0b3d1efe391eedf11e977fac55f9b94f2489c",
		Q0yI: "04bbe48bfd5814648d0b9e30f0717b34015d45a861425fabc1ee06fdfce36384ae2c808185e693ae97dcde118f34de41",
		Q1x:  "19f18cc5ec0c2f055e47c802acc3b0e40c337256a208001dde14b25afced146f37ea3d3ce16834c78175b3ed61f3c537",
		Q1xI: "15b0dadc256a258b4c68ea43605dffa6d312eef215c19e6474b3e101d33b661dfee43b51abbf96fee68fc6043ac56a58",
		Q1y:  "05e47c1781286e61c7ade887512bd9c2cb9f640d3be9cf87ea0bad24bd0ebfe946497b48a581ab6c7d4ca74b5147287f",
		Q1yI: "19f98db2f4a1fcdf56a9ced7b320ea9deecf57c8e59236b0dc21f6ee7229aa9705ce9ac7fe7a31c72edca0d92370c096",
	}, {
		Msg:  "abcdef0123456789",
		Px:   "121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4c0028add35aea8bb83d53c08cfc007c1e005723cd0",
		PxI:  "190d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cbba169fb3968288b3fafb265f9ebd380512a71c3f2c",
		Py:   "05571a0f8d3c08d094576981f4a3b8eda0a8e771fcdcc8ecceaf1356a6acf17574518acb506e435b639353c2e14827c8",
		PyI:  "0bb5e7572275c567462d91807de765611490205a941a5a6af3b1691bfe596c31225d3aabdf15faff860cb4ef17c7c3be",
		U0:   "0313d9325081b415bfd4e5364efaef392ecf69b087496973b229303e1816d2080971470f7da112c4eb43053130b785e1",
		U0I:  "062f84cb21ed89406890c051a0e8b9cf6c575cf6e8e18ecf63ba86826b0ae02548d83b483b79e48512b82a6c0686df8f",
		U1:   "1739123845406baa7be5c5dc74492051b6d42504de008c635f3535bb831d478a341420e67dcc7b46b2e8cba5379cca97",
		U1I:  "01897665d9cb5db16a27657760bbea7951f67ad68f8d55f7113f24ba6ddd82caef240a9bfa627972279974894701d975",
		Q0x:  "0f48f1ea1318ddb713697708f7327781fb39718971d72a9245b9731faaca4dbaa7cca433d6c434a820c28b18e20ea208",
		Q0xI: "06051467c8f85da5ba2540974758f7a1e0239a5981de441fdd87680a995649c211054869c50edbac1f3a86c561ba3162",
		Q0y:  "168b3d6df80069dbbedb714d41b32961ad064c227355e1ce5fac8e105de5e49d77f0c64867f3834848f152497eb76333",
		Q0yI: "134e0e8331cee8cb12f9c2d0742714ed9eee78a84d634c9a95f6a7391b37125ed48bfc6e90bf3546e99930ff67cc97bc",
		Q1x:  "004fd03968cd1c99a0dd84551f44c206c84dcbdb78076c5bfee24e89a92c8508b52b88b68a92258403cbe1ea2da3495f",
		Q1xI: "1674338ea298281b636b2eb0fe593008d03171195fd6dcd4531e8a1ed1f02a72da238a17a635de307d7d24aa2d969a47",
		Q1y:  "0dc7fa13fff6b12558419e0a1e94bfc3cfaf67238009991c5f24ee94b632c3d09e27eca329989aee348a67b50d5e236c",
		Q1yI: "169585e164c131103d85324f2d7747b23b91d66ae5d947c449c8194a347969fc6bbd967729768da485ba71868df8aed2",
	}, {
		Msg: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" +
			"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
		Px:   "19a84dd7248a1066f737cc34502ee5555bd3c19f2ecdb3c7d9e24dc65d4e25e50d83f0f77105e955d78f4762d33c17da",
		PxI:  "0934aba516a52d8ae479939a91998299c76d39cc0c035cd18813bec433f587e2d7a4fef038260eef0cef4d02aae3eb91",
		Py:   "14f81cd421617428bc3b9fe25afbb751d934a00493524bc4e065635b0555084dd54679df1536101b2c979c0152d09192",
		PyI:  "09bcccfa036b4847c9950780733633f13619994394c23ff0b32fa6b795844f4a0673e20282d07bc69641cee04f5e5662",
		U0:   "025820cefc7d06fd38de7d8e370e0da8a52498be9b53cba9927b2ef5c6de1e12e12f188bbc7bc923864883c57e49e253",
		U0I:  "034147b77ce337a52e5948f66db0bab47a8d038e712123bb381899b6ab5ad20f02805601e6104c29df18c254b8618c7b",
		U1:   "0930315cae1f9a6017c3f0c8f2314baa130e1cf13f6532bff0a8a1790cd70af918088c3db94bda214e896e1543629795",
		U1I:  "10c4df2cacf67ea3cb3108b00d4cbd0b3968031ebc8eac4b1ebcefe84d6b715fde66bef0219951ece29d1facc8a520ef",
		Q0x:  "09eccbc53df677f0e5814e3f86e41e146422834854a224bf5a83a50e4cc0a77bfc56718e8166ad180f53526ea9194b57",
		Q0xI: "0c3633943f91daee715277bd644fba585168a72f96ded64fc5a384cce4ec884a4c3c30f08e09cd2129335dc8f67840ec",
		Q0y:  "0eb6186a0457d5b12d132902d4468bfeb7315d83320b6c32f1c875f344efcba979952b4aa418589cb01af712f98cc555",
		Q0yI: "119e3cf167e69eb16c1c7830e8df88856d48be12e3ff0a40791a5cd2f7221311d4bf13b1847f371f467357b3f3c0b4c7",
		Q1x:  "0eb3aabc1ddfce17ff18455fcc7167d15ce6b60ddc9eb9b59f8d40ab49420d35558686293d046fc1e42f864b7f60e381",
		Q1xI: "198bdfb19d7441ebcca61e8ff774b29d17da16547d2c10c273227a635cacea3f16826322ae85717630f0867539b5ed8b",
		Q1y:  "0aaf1dee3adf3ed4c80e481c09b57ea4c705e1b8d25b897f0ceeec3990748716575f92abff22a1c8f4582aff7b872d52",
		Q1yI: "0d058d9061ed27d4259848a06c96c5ca68921a5d269b078650c882cb3c2bd424a8702b7a6ee4e0ead9982baf6843e924",
	}, {
		Msg: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Px:   "01a6ba2f9a11fa5598b2d8ace0fbe0a0eacb65deceb476fbbcb64fd24557c2f4b18ecfc5663e54ae16a84f5ab7f62534",
		PxI:  "11fca2ff525572795a801eed17eb12785887c7b63fb77a42be46ce4a34131d71f7a73e95fee3f812aea3de78b4d01569",
		Py:   "0b6798718c8aed24bc19cb27f866f1c9effcdbf92397ad6448b5c9db90d2b9da6cbabf48adc1adf59a1a28344e79d57e",
		PyI:  "03a47f8e6d1763ba0cad63d6114c0accbef65707825a511b251a660a9b3994249ae4e63fac38b23da0c398689ee2ab52",
		U0:   "190b513da3e66fc9a3587b78c76d1d132b1152174d0b83e3c1114066392579a45824c5fa17649ab89299ddd4bda54935",
		U0I:  "12ab625b0fe0ebd1367fe9fac57bb1168891846039b4216b9d94007b674de2d79126870e88aeef54b2ec717a887dcf39",
		U1:   "0e6a42010cf435fb5bacc156a585e1ea3294cc81d0ceb81924d95040298380b164f702275892cedd81b62de3aba3f6b5",
		U1I:  "117d9a0defc57a33ed208428cb84e54c85a6840e7648480ae428838989d25d97a0af8e3255be62b25c2a85630d2dddd8",
		Q0x:  "17cadf8d04a1a170f8347d42856526a24cc466cb2ddfd506cff01191666b7f944e31244d662c904de5440516a2b09004",
		Q0xI: "0d13ba91f2a8b0051cf3279ea0ee63a9f19bc9cb8bfcc7d78b3cbd8cc4fc43ba726774b28038213acf2b0095391c523e",
		Q0y:  "17ef19497d6d9246fa94d35575c0f8d06ee02f21a284dbeaa78768cb1e25abd564e3381de87bda26acd04f41181610c5",
		Q0yI: "12c3c913ba4ed03c24f0721a81a6be7430f2971ffca8fd1729aafe496bb725807531b44b34b59b3ae5495e5a2dcbd5c8",
		Q1x:  "16ec57b7fe04c71dfe34fb5ad84dbce5a2dbbd6ee085f1d8cd17f45e8868976fc3c51ad9eeda682c7869024d24579bfd",
		Q1xI: "13103f7aace1ae1420d208a537f7d3a9679c287208026e4e3439ab8cd534c12856284d95e27f5e1f33eec2ce656533b0",
		Q1y:  "0958b2c4c2c10fcef5a6c59b9e92c4a67b0fae3e2e0f1b6b5edad9c940b8f3524ba9ebbc3f2ceb3cfe377655b3163bd7",
		Q1yI: "0ccb594ed8bd14ca64ed9cb4e0aba221be540f25dd0d6ba15a4a4be5d67bcf35df7853b2d8dad3ba245f1ea3697f66aa",
	}},
}
