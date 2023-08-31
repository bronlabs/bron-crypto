package p256_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/core/curves/p256"
)

type testCase struct {
	message string
	x       string
	y       string
}

func Test_HashToPointP256(t *testing.T) {
	t.Parallel()

	curve := p256.New()

	// https://datatracker.ietf.org/doc/html/rfc9380 (Appendix J)
	tests := []testCase{
		{
			message: "",
			x:       "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
			y:       "8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415",
		},
		{
			message: "abc",
			x:       "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
			y:       "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e",
		},
		{
			message: "abcdef0123456789",
			x:       "65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
			y:       "cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3",
		},
		{
			message: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
			x:       "4be61ee205094282ba8a2042bcb48d88dfbb609301c49aa8b078533dc65a0b5d",
			y:       "98f8df449a072c4721d241a3b1236d3caccba603f916ca680f4539d2bfb3c29e",
		},
		{
			message: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			x:       "457ae2981f70ca85d8e24c308b14db22f3e3862c5ea0f652ca38b5e49cd64bc5",
			y:       "ecb9f0eadc9aeed232dabc53235368c1394c78de05dd96893eefa62b0f4757dc",
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

	curve := p256.New()
	aNat, err := new(saferith.Nat).SetHex(strings.ToUpper("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"))
	require.NoError(t, err)
	a, err := new(p256.FieldElementP256).SetNat(aNat)
	require.NoError(t, err)
	bNat, err := new(saferith.Nat).SetHex(strings.ToUpper("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"))
	require.NoError(t, err)
	b, err := new(p256.FieldElementP256).SetNat(bNat)
	require.NoError(t, err)

	x := new(p256.FieldElementP256).New(0xCafeBabe)
	y, ok := (x.Mul(x).Mul(x).Add(x.Mul(a)).Add(b)).Sqrt()
	require.True(t, ok)

	pEven, pOdd, err := curve.DeriveAffine(x)
	require.NoError(t, err)

	require.Zero(t, pOdd.Y().Cmp(y))
	require.True(t, pOdd.Y().IsOdd())
	require.Zero(t, pEven.Y().Cmp(y.Neg()))
	require.True(t, pEven.Y().IsEven())
}
