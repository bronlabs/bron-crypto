package impl_test

import (
	"encoding/hex"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/fourq/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/fourq/impl/internal"
)

/**
 * Test vectors generated using sage:
 * sage: fp2.<i> = GF((2^127 - 1)^2, modulus=x^2+1)
 * sage: x = fp2.random_element()
 * sage: y = fp2.random_element()
**/

func dehex(re, im string) *impl.Fp2 {
	var reData, imData [16]byte

	reBytes, err := hex.DecodeString(re)
	if err != nil {
		panic(err)
	}
	imBytes, err := hex.DecodeString(im)
	if err != nil {
		panic(err)
	}
	copy(reData[16-len(reBytes):], reBytes)
	copy(imData[16-len(imBytes):], imBytes)
	slices.Reverse(reData[:])
	slices.Reverse(imData[:])

	var result impl.Fp2
	internal.FpFromBytes(&result.Re, &reData)
	internal.FpFromBytes(&result.Im, &imData)
	return &result
}

func Test_Add(t *testing.T) {
	x := dehex("6f5894b0c7fd3a7d274893865bdce718", "5a4dbf08b27915dedf359f6986e8f88c")
	y := dehex("177ab072bf46fcaef5d64147cc86ee89", "092416597ef6eb4a5b978059855f478e")
	expected := dehex("06d345238744372c1d1ed4ce2863d5a2", "6371d562317001293acd1fc30c48401a")

	z := new(impl.Fp2).Add(x, y)
	require.Equal(t, uint64(1), z.Equal(expected))
}

func Test_Sub(t *testing.T) {
	x := dehex("6e738cd173494afbf1f10f28451af4a9", "35fe48a9f05b6715e392b58f5a4ccf78")
	y := dehex("69c8d06cb8073d7c29b767fb19ff6202", "4704c95f6a22dec6a8c8bfe7f951e8dc")
	expected := dehex("04aabc64bb420d7fc839a72d2b1b92a7", "6ef97f4a8638884f3ac9f5a760fae69b")

	z := new(impl.Fp2).Sub(x, y)
	require.Equal(t, uint64(1), z.Equal(expected))
}

func Test_Mul(t *testing.T) {
	x := dehex("49a6ab6c8469baf3dbf2f767e953aad8", "14948b6faf037a21a892a5e1253978b5")
	y := dehex("5fc88b3598a1fe09fe703eca4a63025f", "7d4effda01a4eff6628c1c90322e39f4")
	expected := dehex("0423f31046eee60ef5435466dead9e4d", "041e2001b1def5b0bc4e821a9f6f56f2")

	z := new(impl.Fp2).Mul(x, y)
	require.Equal(t, uint64(1), z.Equal(expected))
}

func Test_Neg(t *testing.T) {
	x := dehex("1a222ec49c990f18eaf920d134a15889", "527e964abec1234c2889130291722374")
	expected := dehex("65ddd13b6366f0e71506df2ecb5ea776", "2d8169b5413edcb3d776ecfd6e8ddc8b")

	z := new(impl.Fp2).Neg(x)
	require.Equal(t, uint64(1), z.Equal(expected))
}

func Test_Inv(t *testing.T) {
	x := dehex("1632f276e5bc682c557d7126eeb4f4d6", "4b25087227638c250cfc75007309c543")
	expected := dehex("04ed3e0fbc86643af04579dc135d955e", "38ac7687cf964da4a8d86ed69acdeefe")

	z, ok := new(impl.Fp2).Inv(x)
	require.Equal(t, uint64(1), ok)
	require.Equal(t, uint64(1), z.Equal(expected))
}

func Test_Square(t *testing.T) {
	x := dehex("147c5bc34b1de9e138dc5ef07c499b49", "30d7035c4c1a3f5dbee24a3832c48541")
	expected := dehex("27a3a71bb0404441a7e23db488695365", "0185f8ffbc3fe27a3c1b996feb59c2bc")

	z := new(impl.Fp2).Square(x)
	require.Equal(t, uint64(1), z.Equal(expected))
}

func Test_Sqrt(t *testing.T) {
	x := dehex("7ef50e71d520e675fdc8c08c96816da0", "016561a74e94adfa92352c5c5aa40110")
	expected := dehex("5ccfa1dd60578baa3aa03bae4b7710f1", "256c75fd363794f3cd3b397fe4b7403e")

	z, ok := new(impl.Fp2).Sqrt(x)
	require.Equal(t, uint64(1), ok)
	require.Equal(t, uint64(1), z.Equal(expected))
}

func Test_SetUint64(t *testing.T) {
	x := new(impl.Fp2).SetUint64(0xdeadbeefcafebabe)
	y := new(impl.Fp2).SetUint64(0x0badc0de55555555)
	expected := dehex("0a289a6209de76ab15756f5e11ab1716", "")

	z := new(impl.Fp2).Mul(x, y)
	require.Equal(t, uint64(1), z.Equal(expected))
}

func Test_CmpGreater(t *testing.T) {
	const n = 256

	for range n {
		xRe := rand.N[uint64](4096)
		xIm := rand.N[uint64](4096)
		yRe := rand.N[uint64](4096)
		yIm := rand.N[uint64](4096)

		x := &impl.Fp2{
			Re: internal.FpTightFieldElement{xRe},
			Im: internal.FpTightFieldElement{xIm},
		}
		y := &impl.Fp2{
			Re: internal.FpTightFieldElement{yRe},
			Im: internal.FpTightFieldElement{yIm},
		}

		g := x.IsLexicographicallyGreater(y)
		if (xRe > yRe) || ((xRe == yRe) && (xIm > yIm)) {
			require.Equal(t, uint64(1), g)
		} else {
			require.Equal(t, uint64(0), g)
		}
	}
}
