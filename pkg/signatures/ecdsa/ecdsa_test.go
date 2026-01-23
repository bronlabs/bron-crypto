package ecdsa_test

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	curve := k256.NewCurve()
	hashFunc := sha256.New
	suite, err := ecdsa.NewSuite(curve, hashFunc)
	require.NoError(t, err)
	var message [64]byte
	_, err = io.ReadFull(prng, message[:])
	require.NoError(t, err)

	skValue, err := k256.NewScalarField().Random(prng)
	require.NoError(t, err)
	pkValue := k256.NewCurve().ScalarBaseMul(skValue)

	pk, err := ecdsa.NewPublicKey(pkValue)
	require.NoError(t, err)
	sk, err := ecdsa.NewPrivateKey(skValue, pk)
	require.NoError(t, err)

	scheme, err := ecdsa.NewScheme(suite, prng)
	require.NoError(t, err)
	signer, err := scheme.Signer(sk)
	require.NoError(t, err)
	signature, err := signer.Sign(message[:])
	require.NoError(t, err)
	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	err = verifier.Verify(signature, pk, message[:])
	require.NoError(t, err)

	recoveredPk, err := ecdsa.RecoverPublicKey(suite, signature, message[:])
	require.NoError(t, err)
	require.True(t, recoveredPk.Equal(pk))
}

func Test_HappyPathSha3(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	curve := k256.NewCurve()
	hashFunc := sha3.New256
	suite, err := ecdsa.NewSuite(curve, hashFunc)
	require.NoError(t, err)
	var message [64]byte
	_, err = io.ReadFull(prng, message[:])
	require.NoError(t, err)

	skValue, err := k256.NewScalarField().Random(prng)
	require.NoError(t, err)
	pkValue := k256.NewCurve().ScalarBaseMul(skValue)

	pk, err := ecdsa.NewPublicKey(pkValue)
	require.NoError(t, err)
	sk, err := ecdsa.NewPrivateKey(skValue, pk)
	require.NoError(t, err)

	scheme, err := ecdsa.NewScheme(suite, prng)
	require.NoError(t, err)
	signer, err := scheme.Signer(sk)
	require.NoError(t, err)
	signature, err := signer.Sign(message[:])
	require.NoError(t, err)
	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	err = verifier.Verify(signature, pk, message[:])
	require.NoError(t, err)

	recoveredPk, err := ecdsa.RecoverPublicKey(suite, signature, message[:])
	require.NoError(t, err)
	require.True(t, recoveredPk.Equal(pk))
}

func Test_DeterministicHappyPath(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	hashId := crypto.SHA256
	curve := p256.NewCurve()
	suite, err := ecdsa.NewDeterministicSuite(curve, hashId)
	require.NoError(t, err)
	var message [64]byte
	_, err = io.ReadFull(prng, message[:])
	require.NoError(t, err)

	skValue, err := p256.NewScalarField().Random(prng)
	require.NoError(t, err)
	pkValue := p256.NewCurve().ScalarBaseMul(skValue)

	pk, err := ecdsa.NewPublicKey(pkValue)
	require.NoError(t, err)
	sk, err := ecdsa.NewPrivateKey(skValue, pk)
	require.NoError(t, err)

	scheme, err := ecdsa.NewScheme(suite, prng)
	require.NoError(t, err)
	signer, err := scheme.Signer(sk)
	require.NoError(t, err)
	signature1, err := signer.Sign(message[:])
	require.NoError(t, err)
	signature2, err := signer.Sign(message[:])
	require.NoError(t, err)

	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	err = verifier.Verify(signature1, pk, message[:])
	require.NoError(t, err)
	err = verifier.Verify(signature2, pk, message[:])
	require.NoError(t, err)

	require.True(t, signature1.Equal(signature2))

	recoveredPk1, err := ecdsa.RecoverPublicKey(suite, signature1, message[:])
	require.NoError(t, err)
	require.True(t, recoveredPk1.Equal(pk))

	recoveredPk2, err := ecdsa.RecoverPublicKey(suite, signature2, message[:])
	require.NoError(t, err)
	require.True(t, recoveredPk2.Equal(pk))
}

func Test_RFC6979(t *testing.T) {
	t.Parallel()

	type testVector struct {
		message string
		hashId  crypto.Hash
		r       string
		s       string
	}

	curve := p256.NewCurve()
	skHex := "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
	skBytes, err := hex.DecodeString(skHex)
	require.NoError(t, err)
	skValue, err := curve.ScalarField().FromWideBytes(skBytes)
	require.NoError(t, err)
	pkValue := curve.ScalarBaseMul(skValue)

	publicKey, err := ecdsa.NewPublicKey(pkValue)
	require.NoError(t, err)
	secretKey, err := ecdsa.NewPrivateKey(skValue, publicKey)
	require.NoError(t, err)

	testVectors := []testVector{
		{
			message: "sample",
			hashId:  crypto.SHA1,
			r:       "61340C88C3AAEBEB4F6D667F672CA9759A6CCAA9FA8811313039EE4A35471D32",
			s:       "6D7F147DAC089441BB2E2FE8F7A3FA264B9C475098FDCF6E00D7C996E1B8B7EB",
		},
		{
			message: "sample",
			hashId:  crypto.SHA224,
			r:       "53B2FFF5D1752B2C689DF257C04C40A587FABABB3F6FC2702F1343AF7CA9AA3F",
			s:       "B9AFB64FDC03DC1A131C7D2386D11E349F070AA432A4ACC918BEA988BF75C74C",
		},
		{
			message: "sample",
			hashId:  crypto.SHA256,
			r:       "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
			s:       "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
		},
		{
			message: "sample",
			hashId:  crypto.SHA384,
			r:       "0EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF7719",
			s:       "4861F0491E6998B9455193E34E7B0D284DDD7149A74B95B9261F13ABDE940954",
		},
		{
			message: "sample",
			hashId:  crypto.SHA512,
			r:       "8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00",
			s:       "2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE",
		},
		{
			message: "test",
			hashId:  crypto.SHA1,
			r:       "0CBCC86FD6ABD1D99E703E1EC50069EE5C0B4BA4B9AC60E409E8EC5910D81A89",
			s:       "01B9D7B73DFAA60D5651EC4591A0136F87653E0FD780C3B1BC872FFDEAE479B1",
		},
		{
			message: "test",
			hashId:  crypto.SHA224,
			r:       "C37EDB6F0AE79D47C3C27E962FA269BB4F441770357E114EE511F662EC34A692",
			s:       "C820053A05791E521FCAAD6042D40AEA1D6B1A540138558F47D0719800E18F2D",
		},
		{
			message: "test",
			hashId:  crypto.SHA256,
			r:       "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
			s:       "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083",
		},
		{
			message: "test",
			hashId:  crypto.SHA384,
			r:       "83910E8B48BB0C74244EBDF7F07A1C5413D61472BD941EF3920E623FBCCEBEB6",
			s:       "8DDBEC54CF8CD5874883841D712142A56A8D0F218F5003CB0296B6B509619F2C",
		},
		{
			message: "test",
			hashId:  crypto.SHA512,
			r:       "461D93F31B6540894788FD206C07CFA0CC35F46FA3C91816FFF1040AD1581A04",
			s:       "39AF9F15DE0DB8D97E72719C74820D304CE5226E32DEDAE67519E840D1194E55",
		},
	}

	for _, v := range testVectors {
		suite, err := ecdsa.NewDeterministicSuite(curve, v.hashId)
		require.NoError(t, err)
		signer, err := ecdsa.NewSigner(suite, secretKey, nil)
		require.NoError(t, err)
		signature, err := signer.Sign([]byte(v.message))
		require.NoError(t, err)

		require.Equal(t, v.r, strings.ToUpper(hex.EncodeToString(signature.R().Bytes())))
		require.Equal(t, v.s, strings.ToUpper(hex.EncodeToString(signature.S().Bytes())))
	}
}
