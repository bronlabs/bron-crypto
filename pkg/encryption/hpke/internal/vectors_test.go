//nolint:testpackage // Allow testing of unexported functions
package internal

import (
	"crypto"
	"fmt"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/stretchr/testify/require"
)

func setup[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](t *testing.T, s *SetupInfo_Testing, kem *DHKEMScheme[P, B, S]) (*ReceiverContext, *SenderContext[P, B, S]) {
	t.Helper()

	cipherSuite := &CipherSuite{
		kdf:  s.KDFID,
		kem:  s.KEMID,
		aead: s.AEADID,
	}

	ephemeralPrivateKey, ephemeralPublicKey, err := kem.DeriveKeyPair(s.IkmE)
	require.NoError(t, err)
	require.EqualValues(t, s.SkEm, ephemeralPrivateKey.Value().Bytes())
	require.EqualValues(t, s.PkEm, ephemeralPublicKey.Value().ToUncompressed())

	receiverPrivateKey, receiverPublicKey, err := kem.DeriveKeyPair(s.IkmR)
	require.NoError(t, err)

	require.EqualValues(t, s.SkRm, receiverPrivateKey.Value().Bytes())
	require.EqualValues(t, s.PkRm, receiverPublicKey.Value().ToUncompressed())

	var sharedSecret []byte
	var senderPrivateKey *PrivateKey[S]
	var senderPublicKey *PublicKey[P, B, S]
	if s.Mode == Auth || s.Mode == AuthPSk {
		senderPrivateKey, senderPublicKey, err = kem.DeriveKeyPair(s.IkmS)
		require.NoError(t, err)

		require.EqualValues(t, s.SkSm, senderPrivateKey.Value().Bytes())
		require.EqualValues(t, s.PkSm, senderPublicKey.Value().ToUncompressed())

		sharedSecret, ephemeralPublicKey, err = kem.AuthEncapWithIKM(receiverPublicKey, senderPrivateKey, s.IkmE)
		require.NoError(t, err)
		sharedSecretDecap, err := kem.AuthDecap(receiverPrivateKey, senderPublicKey, ephemeralPublicKey)
		require.NoError(t, err)
		require.EqualValues(t, sharedSecret, sharedSecretDecap)

	} else {
		sharedSecret, ephemeralPublicKey, err = kem.EncapWithIKM(receiverPublicKey, s.IkmE)
		require.NoError(t, err)
		sharedSecretDecap, err := kem.Decap(receiverPrivateKey, ephemeralPublicKey)
		require.NoError(t, err)
		require.EqualValues(t, sharedSecret, sharedSecretDecap)
	}
	require.EqualValues(t, s.Enc, ephemeralPublicKey.Value().ToUncompressed())
	require.EqualValues(t, s.SharedSecret, sharedSecret)

	ctx, keyScheduleCtx, err := keySchedule(ReceiverRole, cipherSuite, s.Mode, sharedSecret, s.Info, s.PSk, s.PSkID)
	require.NoError(t, err)
	require.EqualValues(t, s.KeyScheduleContext, keyScheduleCtx.Marshal())
	require.EqualValues(t, s.Secret, ctx.secret)
	require.EqualValues(t, s.BaseNonce, ctx.baseNonce)
	require.EqualValues(t, s.Key, ctx.key)
	require.EqualValues(t, s.ExporterSecret, ctx.exporterSecret)

	receiverContext := &ReceiverContext{
		c: ctx,
	}
	var senderContext *SenderContext[P, B, S]
	if senderPrivateKey != nil {
		ctx, _, err := keySchedule(SenderRole, cipherSuite, s.Mode, sharedSecret, s.Info, s.PSk, s.PSkID)
		require.NoError(t, err)
		senderContext = &SenderContext[P, B, S]{
			Capsule: ephemeralPublicKey,
			c:       ctx,
		}
	}
	return receiverContext, senderContext
}

func openCiphertext(t *testing.T, receiver *ReceiverContext, tt *EncryptionInfo_Testing) {
	t.Helper()
	receiver.c.sequence = tt.Seq
	require.False(t, receiver.c.nonces.Contains(tt.Nonce))
	decrypted, err := receiver.Open(tt.Ct, tt.Aad)
	require.NoError(t, err)
	require.EqualValues(t, tt.Pt, decrypted)
	require.Equal(t, tt.Seq+1, receiver.c.sequence)
	require.True(t, receiver.c.nonces.Contains(tt.Nonce))
}

func sealPlaintext[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](t *testing.T, sender *SenderContext[P, B, S], tt *EncryptionInfo_Testing) {
	t.Helper()
	sender.c.sequence = tt.Seq
	require.False(t, sender.c.nonces.Contains(tt.Nonce))
	ciphertext, err := sender.Seal(tt.Pt, tt.Aad)
	require.NoError(t, err)
	require.EqualValues(t, tt.Ct, ciphertext)
	require.Equal(t, tt.Seq+1, sender.c.sequence)
	require.True(t, sender.c.nonces.Contains(tt.Nonce))
}

// Test https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A
func TestRFCTestVectors(t *testing.T) {
	t.Parallel()
	for _, suiteCase := range TestVectors {
		for _, authSuiteCase := range suiteCase.Auths {
			t.Run(fmt.Sprintf("%s | mode: %v", suiteCase.Name, authSuiteCase.Mode), func(t *testing.T) {
				t.Parallel()
				for _, test := range authSuiteCase.Encryptions {
					t.Run(fmt.Sprintf("running encryption test for seq %d", test.Seq), func(t *testing.T) {
						t.Parallel()
						if authSuiteCase.Setup.KEMID != DHKEM_P256_HKDF_SHA256 {
							t.Skip()
						}
						kdf, err := NewKDF(authSuiteCase.Setup.KDFID)
						require.NoError(t, err)
						if kdf.hash != crypto.SHA256 {
							t.Skip()
						}
						kem, err := NewDHKEM(p256.NewCurve(), kdf)
						require.NoError(t, err)
						receiver, sender := setup(t, authSuiteCase.Setup, kem)
						openCiphertext(t, receiver, test)
						if authSuiteCase.Mode == Auth || authSuiteCase.Mode == AuthPSk {
							require.NotNil(t, sender)
							sealPlaintext(t, sender, test)
						}
					})
				}

				for i, test := range authSuiteCase.Exports {
					t.Run(fmt.Sprintf("running export test for iteration %d", i), func(t *testing.T) {
						t.Parallel()
						if authSuiteCase.Setup.KEMID != DHKEM_P256_HKDF_SHA256 {
							t.Skip()
						}
						kdf, err := NewKDF(authSuiteCase.Setup.KDFID)
						require.NoError(t, err)
						if kdf.hash != crypto.SHA256 {
							t.Skip()
						}
						kem, err := NewDHKEM(p256.NewCurve(), kdf)
						require.NoError(t, err)
						receiver, sender := setup(t, authSuiteCase.Setup, kem)
						secret, err := receiver.Export(test.ExporterContext, test.L)
						require.NoError(t, err)
						require.EqualValues(t, test.ExportedValue, secret)
						if authSuiteCase.Mode == Auth || authSuiteCase.Mode == AuthPSk {
							require.NotNil(t, sender)
							secret, err := sender.Export(test.ExporterContext, test.L)
							require.NoError(t, err)
							require.EqualValues(t, test.ExportedValue, secret)
						}
					})
				}
			})
		}
	}
}
