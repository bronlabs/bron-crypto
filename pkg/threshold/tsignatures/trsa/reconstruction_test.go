package trsa_test

import (
	"crypto"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/combinatorics"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa/dkg"
)

const (
	total     = 3
	threshold = 2
)

func Test_ReconstructionHappyPath(t *testing.T) {
	t.Parallel()
	var err error

	prng := crand.Reader

	identities, err := testutils.MakeDeterministicTestIdentities(total)
	require.NoError(t, err)

	protocol, err := testutils.MakeThresholdProtocol(k256.NewCurve(), identities, threshold)
	require.NoError(t, err)

	sessionId := []byte("session-id-test")
	tapes := testutils.MakeTranscripts("transcript-test", identities)

	participants := make([]*dkg.Participant, len(identities))
	for i, id := range identities {
		participants[i], err = dkg.NewParticipant(sessionId, id.(types.AuthKey), protocol, tapes[i], prng)
		require.NoError(t, err)
	}

	r1bo := make([]*dkg.Round1Broadcast, total)
	r1uo := make([]network.RoundMessages[types.ThresholdProtocol, *dkg.Round1P2P], total)
	for i, p := range participants {
		r1bo[i], r1uo[i], err = p.Round1()
		require.NoError(t, err)
	}

	r2bi, r2ui := testutils.MapO2I(t, participants, r1bo, r1uo)
	shards := make([]*trsa.Shard, total)
	for i, p := range participants {
		shards[i], err = p.Round2(r2bi[i], r2ui[i])
		require.NoError(t, err)
	}
	publicKey := shards[0].PublicKey()

	for th := threshold; th <= total; th++ {
		shardsSubsets, err := combinatorics.Combinations(shards, uint(th))
		require.NoError(t, err)

		for _, shardsSubset := range shardsSubsets {
			reconstructedPrivateKey, err := trsa.ConstructPrivateKey(prng, shardsSubset...)
			require.NoError(t, err)

			t.Run("sign with reconstructed private key", func(t *testing.T) {
				t.Parallel()

				h := crypto.SHA256
				message := []byte("hello universe")
				hasher := h.New()
				_, err := hasher.Write(message)
				require.NoError(t, err)
				digest := hasher.Sum(nil)

				signature, err := rsa.SignPSS(prng, reconstructedPrivateKey, h, digest, nil)
				require.NoError(t, err)

				err = rsa.VerifyPSS(publicKey, h, digest, signature, nil)
				require.NoError(t, err)
			})

			t.Run("decrypt with reconstructed private key", func(t *testing.T) {
				t.Parallel()

				h := sha256.New
				message := []byte("hello world")
				encrypted, err := rsa.EncryptOAEP(h(), prng, publicKey, message, nil)
				require.NoError(t, err)

				decrypted, err := rsa.DecryptOAEP(h(), prng, reconstructedPrivateKey, encrypted, nil)
				require.NoError(t, err)
				require.Equal(t, message, decrypted)
			})
		}
	}
}
