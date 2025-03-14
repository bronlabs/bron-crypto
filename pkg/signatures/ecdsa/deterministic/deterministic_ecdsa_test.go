package deterministic_test

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa/deterministic"
)

func Test_DeterministicECDSA_RFC6979(t *testing.T) {
	t.Parallel()

	// Test vector from RFC6979 (https://tools.ietf.org/html/rfc6979#appendix-A.2.5)
	curve := p256.NewCurve()

	privateKey, publicKey, testCases := testVectorRFC6979_P256(t)

	for i := range testCases {
		i := i
		t.Run(fmt.Sprintf("Message:\"%s\" HashSize:%dB", testCases[i].Message, testCases[i].HashFunc().Size()), func(t *testing.T) {
			t.Parallel()
			protocol, err := types.NewSigningSuite(curve, testCases[i].HashFunc)
			require.NoError(t, err)
			signer, err := deterministic.NewSigner(protocol, privateKey)
			require.NoError(t, err)

			// Sign the Messages
			signature, err := signer.Sign(testCases[i].Message)
			require.NoError(t, err)

			// Verify the signature
			require.NoError(t, ecdsa.Verify(signature, testCases[i].HashFunc, publicKey, testCases[i].Message))

			// Verify that the signature is deterministic
			require.True(t, signature.R.Equal(testCases[i].Signature.R))
			require.True(t, signature.S.Equal(testCases[i].Signature.S))
		})
	}
}

type TestCase struct {
	HashFunc  func() hash.Hash
	Message   []byte
	Signature ecdsa.Signature
}

// Test vector from RFC6979 (https://tools.ietf.org/html/rfc6979#appendix-A.2.5)
func testVectorRFC6979_P256(t *testing.T) (privateKey curves.Scalar, publicKey curves.Point, testCases []TestCase) {
	t.Helper()

	curve := p256.NewCurve()

	privateKey = stringToScalar(t, curve,
		"C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")
	publicKey = stringToPoint(t, curve,
		"60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
		"7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299")
	require.True(t, publicKey.Equal(curve.ScalarBaseMult(privateKey)))

	testCases = []TestCase{
		{
			HashFunc: sha256.New,
			Message:  []byte("sample"),
			Signature: ecdsa.Signature{
				R: stringToScalar(t, curve, "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"),
				S: stringToScalar(t, curve, "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"),
			},
		},
		{
			HashFunc: sha256.New,
			Message:  []byte("test"),
			Signature: ecdsa.Signature{
				R: stringToScalar(t, curve, "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367"),
				S: stringToScalar(t, curve, "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083"),
			},
		},
		{
			HashFunc: sha512.New,
			Message:  []byte("sample"),
			Signature: ecdsa.Signature{
				R: stringToScalar(t, curve, "8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00"),
				S: stringToScalar(t, curve, "2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE"),
			},
		}, {
			HashFunc: sha512.New,
			Message:  []byte("test"),
			Signature: ecdsa.Signature{
				R: stringToScalar(t, curve, "461D93F31B6540894788FD206C07CFA0CC35F46FA3C91816FFF1040AD1581A04"),
				S: stringToScalar(t, curve, "39AF9F15DE0DB8D97E72719C74820D304CE5226E32DEDAE67519E840D1194E55"),
			},
		},
	}
	return privateKey, publicKey, testCases
}

func stringToScalar(t *testing.T, curve curves.Curve, s string) curves.Scalar {
	t.Helper()

	xBytes, err := hex.DecodeString(s)
	require.NoError(t, err)
	x, err := curve.ScalarField().Element().SetBytes(xBytes)
	require.NoError(t, err)
	return x
}

func stringToPoint(t *testing.T, curve curves.Curve, x string, y string) curves.Point {
	t.Helper()

	xBytes, err := hex.DecodeString(x)
	require.NoError(t, err)
	yBytes, err := hex.DecodeString(y)
	require.NoError(t, err)
	xFe, err := curve.BaseField().Element().SetBytes(xBytes)
	require.NoError(t, err)
	yFe, err := curve.BaseField().Element().SetBytes(yBytes)
	require.NoError(t, err)
	point, err := curve.NewPoint(xFe, yFe)
	require.NoError(t, err)
	return point
}
