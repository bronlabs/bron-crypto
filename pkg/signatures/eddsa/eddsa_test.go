package eddsa_test

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/eddsa"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr"
	vanillaSchnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
)

// passing of this test by the standard library's ed25519 implementation means that
// we need the small order checks.
// Test vectors are table 6(c) index 0, 1, 11 of https://eprint.iacr.org/2020/1244.pdf
// test vector 10 fails, because the std implementation does not compress the public key before hashing
func TestEd25519VerificationShouldFailForSmallOrderPublicKeys(t *testing.T) {
	t.Parallel()
	suite, err := ttu.MakeSignatureProtocol(edwards25519.NewCurve(), sha512.New)
	require.NoError(t, err)

	// From Page 8 of https://eprint.iacr.org/2020/1244.pdf
	// Any point P of the group E can be uniquely represented as a linear combination of B and
	// T8: P = b · B + t · T8, where b ∈ 0, . . . , L − 1 and t ∈ 0, . . . , 7. We say that the
	// discrete log of P base B is b. We say that a point P is of “small order” iff b = 0,
	// “mixed order” iff t ̸= 0 and b ̸= 0, and “order L” iff b ̸= 0 and t = 0
	for _, test := range []struct {
		message   string
		publicKey string
		signature string
		name      string
	}{
		{
			message:   "8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6",
			publicKey: "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
			signature: "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
			name:      "z=0 | Public key small order and compressed | R small order | test vector 0",
		},
		{
			message:   "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
			publicKey: "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
			signature: "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
			name:      "reduced z | public key small order and compressed | R mixed order | test vector 1",
		},

		// Although the public key order of below (test vector 10) is small, it is designed to fail for implementations that do not compress public key before hashing.
		//
		// {message: "e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b",
		// 	publicKey:   "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		// 	signature: "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04"},

		{
			message:   "39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f",
			publicKey: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			signature: "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
			name:      "reduced z | public key small order and uncompressed | R mised order | test vector 11",
		},
	} {
		boundedTest := test
		t.Run(boundedTest.name, func(t *testing.T) {
			t.Parallel()

			message, err := hex.DecodeString(boundedTest.message)
			require.NoError(t, err)

			publicKeyBytes, err := hex.DecodeString(boundedTest.publicKey)
			require.NoError(t, err)

			signatureBytes, err := hex.DecodeString(boundedTest.signature)
			require.NoError(t, err)

			var publicKeyStd ed25519.PublicKey = publicKeyBytes
			result := ed25519.Verify(publicKeyStd, message, signatureBytes)
			require.True(t, result)

			A, err := suite.Curve().Point().FromAffineCompressed(publicKeyBytes)
			require.NoError(t, err)

			RBytes := signatureBytes[:32]
			sBytes := signatureBytes[32:]

			R, err := suite.Curve().Point().FromAffineCompressed(RBytes)
			require.NoError(t, err)

			s, err := suite.Curve().Scalar().SetBytes(sBytes)
			require.NoError(t, err)

			signature := schnorr.NewSignature(vanillaSchnorr.NewEdDsaCompatibleVariant(), nil, R, s)
			publicKey := &eddsa.PublicKey{
				A: A,
			}

			err = eddsa.Verify(publicKey, message, signature)
			require.Error(t, err)
			require.True(t, errs.IsVerification(err))
		})
	}
}
