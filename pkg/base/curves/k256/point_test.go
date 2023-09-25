package k256_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
)

type testCase struct {
	message string
	x       string
	y       string
}

func Test_HashToPointK256(t *testing.T) {
	t.Parallel()

	curve := k256.New()

	// https://datatracker.ietf.org/doc/html/rfc9380 (Appendix J)
	tests := []testCase{
		{
			message: "",
			x:       "c1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb1346",
			y:       "64fa678e07ae116126f08b022a94af6de15985c996c3a91b64c406a960e51067",
		},
		{
			message: "abc",
			x:       "3377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb2c4b",
			y:       "7f95890f33efebd1044d382a01b1bee0900fb6116f94688d487c6c7b9c8371f6",
		},
		{
			message: "abcdef0123456789",
			x:       "bac54083f293f1fe08e4a70137260aa90783a5cb84d3f35848b324d0674b0e3a",
			y:       "4436476085d4c3c4508b60fcf4389c40176adce756b398bdee27bca19758d828",
		},
		{
			message: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
			x:       "e2167bc785333a37aa562f021f1e881defb853839babf52a7f72b102e41890e9",
			y:       "f2401dd95cc35867ffed4f367cd564763719fbc6a53e969fb8496a1e6685d873",
		},
		{
			message: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			x:       "e3c8d35aaaf0b9b647e88a0a0a7ee5d5bed5ad38238152e4e6fd8c1f8cb7c998",
			y:       "8446eeb6181bf12f56a9d24e262221cc2f0c4725c7e3803024b5888ee5823aa6",
		},
	}

	for i, test := range tests {
		theTest := test
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			ex, err := new(saferith.Nat).SetHex(strings.ToUpper(theTest.x))
			require.NoError(t, err)
			ey, err := new(saferith.Nat).SetHex(strings.ToUpper(theTest.y))
			require.NoError(t, err)
			expected, err := curve.Point().Set(ex, ey)
			require.NoError(t, err)
			p := curve.Point().Hash([]byte(theTest.message))
			require.NoError(t, err)
			require.True(t, p.Equal(expected))
		})
	}
}

func Test_DeriveAffine(t *testing.T) {
	t.Parallel()

	curve := k256.New()
	aNat, err := new(saferith.Nat).SetHex(strings.ToUpper("0000000000000000000000000000000000000000000000000000000000000000"))
	require.NoError(t, err)
	a, err := new(k256.FieldElement).SetNat(aNat)
	require.NoError(t, err)
	require.True(t, a.IsEven())
	bNat, err := new(saferith.Nat).SetHex(strings.ToUpper("0000000000000000000000000000000000000000000000000000000000000007"))
	require.NoError(t, err)
	b, err := new(k256.FieldElement).SetNat(bNat)
	require.NoError(t, err)
	require.True(t, b.IsOdd())

	x := new(k256.FieldElement).New(0xCafeBabe)
	y, ok := (x.Mul(x).Mul(x).Add(x.Mul(a)).Add(b)).Sqrt()
	require.True(t, ok)

	pEven, pOdd, err := curve.DeriveFromAffineX(x)
	require.NoError(t, err)

	require.Zero(t, pEven.Y().Cmp(y))
	require.True(t, pEven.Y().IsEven())
	require.Zero(t, pOdd.Y().Cmp(y.Neg()))
	require.True(t, pOdd.Y().IsOdd())
}
