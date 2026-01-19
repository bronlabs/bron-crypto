//nolint:testpackage // Allow testing of unexported functions
package internal

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
)

func setup[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](t *testing.T, s *SetupInfo_Testing, kem *DHKEMScheme[P, B, S]) (*ReceiverContext[P, B, S], *SenderContext[P, B, S]) {
	t.Helper()

	cipherSuite := &CipherSuite{
		kdf:  s.KDFID,
		kem:  s.KEMID,
		aead: s.AEADID,
	}

	ephemeralPrivateKey, ephemeralPublicKey, err := kem.DeriveKeyPair(s.IkmE)
	require.NoError(t, err)
	require.Equal(t, s.SkEm, ephemeralPrivateKey.Bytes(), "ephemeral private key mismatch")
	require.Equal(t, s.PkEm, ephemeralPublicKey.Bytes(), "ephemeral public key mismatch")

	receiverPrivateKey, receiverPublicKey, err := kem.DeriveKeyPair(s.IkmR)
	require.NoError(t, err)

	require.Equal(t, s.SkRm, receiverPrivateKey.Bytes(), "receiver private key mismatch")
	require.Equal(t, s.PkRm, receiverPublicKey.Bytes(), "receiver public key mismatch")

	var sharedSecret []byte
	var senderPrivateKey *PrivateKey[S]
	var senderPublicKey *PublicKey[P, B, S]
	if s.Mode == Auth || s.Mode == AuthPSk {
		senderPrivateKey, senderPublicKey, err = kem.DeriveKeyPair(s.IkmS)
		require.NoError(t, err)

		require.Equal(t, s.SkSm, senderPrivateKey.Bytes(), "sender private key mismatch")
		require.Equal(t, s.PkSm, senderPublicKey.Bytes(), "sender public key mismatch")

		sharedSecret, ephemeralPublicKey, err = kem.AuthEncapWithIKM(receiverPublicKey, senderPrivateKey, s.IkmE)
		require.NoError(t, err)
		sharedSecretDecap, err := kem.AuthDecap(receiverPrivateKey, senderPublicKey, ephemeralPublicKey)
		require.NoError(t, err)
		require.Equal(t, sharedSecret, sharedSecretDecap)

	} else {
		sharedSecret, ephemeralPublicKey, err = kem.EncapWithIKM(receiverPublicKey, s.IkmE)
		require.NoError(t, err)
		sharedSecretDecap, err := kem.Decap(receiverPrivateKey, ephemeralPublicKey)
		require.NoError(t, err)
		require.Equal(t, sharedSecret, sharedSecretDecap)
	}
	require.Equal(t, s.Enc, ephemeralPublicKey.Bytes(), "encapsulated public key mismatch")
	require.Equal(t, s.SharedSecret, sharedSecret)

	ctx, keyScheduleCtx, err := keySchedule(ReceiverRole, cipherSuite, s.Mode, sharedSecret, s.Info, s.PSk, s.PSkID)
	require.NoError(t, err)
	require.Equal(t, s.KeyScheduleContext, keyScheduleCtx.Marshal())
	require.Equal(t, s.Secret, ctx.secret)
	require.EqualValues(t, s.BaseNonce, ctx.baseNonce)
	require.Equal(t, s.Key, ctx.key)
	require.Equal(t, s.ExporterSecret, ctx.exporterSecret)

	receiverContext := &ReceiverContext[P, B, S]{
		ctx: ctx,
	}
	var senderContext *SenderContext[P, B, S]
	if senderPrivateKey != nil {
		ctx, _, err := keySchedule(SenderRole, cipherSuite, s.Mode, sharedSecret, s.Info, s.PSk, s.PSkID)
		require.NoError(t, err)
		senderContext = &SenderContext[P, B, S]{
			Capsule: ephemeralPublicKey,
			ctx:     ctx,
		}
	}
	return receiverContext, senderContext
}

func openCiphertext[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](t *testing.T, receiver *ReceiverContext[P, B, S], tt *EncryptionInfo_Testing) {
	t.Helper()
	receiver.ctx.sequence = tt.Seq
	require.False(t, receiver.ctx.nonces.Contains(tt.Nonce))
	decrypted, err := receiver.Open(tt.Ct, tt.Aad)
	require.NoError(t, err)
	require.Equal(t, tt.Pt, decrypted)
	require.Equal(t, tt.Seq+1, receiver.ctx.sequence)
	require.True(t, receiver.ctx.nonces.Contains(tt.Nonce))
}

func sealPlaintext[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](t *testing.T, sender *SenderContext[P, B, S], tt *EncryptionInfo_Testing) {
	t.Helper()
	sender.ctx.sequence = tt.Seq
	require.False(t, sender.ctx.nonces.Contains(tt.Nonce))
	ciphertext, err := sender.Seal(tt.Pt, tt.Aad)
	require.NoError(t, err)
	require.Equal(t, tt.Ct, ciphertext)
	require.Equal(t, tt.Seq+1, sender.ctx.sequence)
	require.True(t, sender.ctx.nonces.Contains(tt.Nonce))
}

func runnerEncryption[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](t *testing.T, suiteInfo *SuiteInfo_Testing, kem *DHKEMScheme[P, B, S], test *EncryptionInfo_Testing) {
	t.Helper()
	receiver, sender := setup(t, suiteInfo.Setup, kem)
	openCiphertext(t, receiver, test)
	if suiteInfo.Mode == Auth || suiteInfo.Mode == AuthPSk {
		require.NotNil(t, sender)
		sealPlaintext(t, sender, test)
	}
}

func runnerExport[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](t *testing.T, suiteInfo *SuiteInfo_Testing, kem *DHKEMScheme[P, B, S], test *ExportInfo_Testing) {
	t.Helper()
	receiver, sender := setup(t, suiteInfo.Setup, kem)
	secret, err := receiver.Export(test.ExporterContext, test.L)
	require.NoError(t, err)
	require.Equal(t, test.ExportedValue, secret)
	if suiteInfo.Mode == Auth || suiteInfo.Mode == AuthPSk {
		require.NotNil(t, sender)
		secret, err := sender.Export(test.ExporterContext, test.L)
		require.NoError(t, err)
		require.Equal(t, test.ExportedValue, secret)
	}
}

// Test https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A
func TestRFCTestVectors(t *testing.T) {
	t.Parallel()
	for _, suiteCase := range TestVectors {
		for _, suiteInfo := range suiteCase.Info {
			t.Run(fmt.Sprintf("%s | mode: %v", suiteCase.Name, suiteInfo.Mode), func(t *testing.T) {
				t.Parallel()
				for _, test := range suiteInfo.Encryptions {
					t.Run(fmt.Sprintf("running encryption test for seq %d", test.Seq), func(t *testing.T) {
						t.Parallel()

						switch suiteInfo.Setup.KEMID {
						case DHKEM_P256_HKDF_SHA256:
							kem := NewP256HKDFSha256KEM()
							runnerEncryption(t, suiteInfo, kem, test)
						case DHKEM_X25519_HKDF_SHA256:
							kem := NewX25519HKDFSha256KEM()
							runnerEncryption(t, suiteInfo, kem, test)
						case DHKEM_RESERVED:
							fallthrough
						default:
							require.Fail(t, "KEM ID not supported", suiteInfo.Setup.KEMID)
						}
					})
				}

				for i, test := range suiteInfo.Exports {
					t.Run(fmt.Sprintf("running export test for iteration %d", i), func(t *testing.T) {
						t.Parallel()

						switch suiteInfo.Setup.KEMID {
						case DHKEM_P256_HKDF_SHA256:
							kem := NewP256HKDFSha256KEM()
							runnerExport(t, suiteInfo, kem, test)
						case DHKEM_X25519_HKDF_SHA256:
							kem := NewX25519HKDFSha256KEM()
							runnerExport(t, suiteInfo, kem, test)
						case DHKEM_RESERVED:
							fallthrough
						default:
							require.Fail(t, "KEM ID not supported", suiteInfo.Setup.KEMID)
						}
					})
				}
			})
		}
	}
}
