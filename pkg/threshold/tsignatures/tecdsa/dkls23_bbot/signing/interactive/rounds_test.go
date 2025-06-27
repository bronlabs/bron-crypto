package interactive_test

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/combinatorics"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	ttu "github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/dkls23/keygen/trusted_dealer"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/dkls23/signing"
	dkls_bbot_sign "github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/dkls23_bbot/signing/interactive"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	const N = 3
	const T = 2
	prng := crand.Reader
	curve := k256.NewCurve()
	hashFunc := sha256.New

	signingSuite, err := ttu.MakeSigningSuite(curve, hashFunc)
	require.NoError(t, err)

	identities, err := ttu.MakeDeterministicTestIdentities(N)
	require.NoError(t, err)

	protocol, err := ttu.MakeThresholdSignatureProtocol(signingSuite, identities, T, identities)
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen(protocol, crand.Reader)
	require.NoError(t, err)

	sessionId := []byte("test session id")
	tape := hagrid.NewTranscript("test test", prng)

	for threshold := T; threshold <= N; threshold++ {
		combinations, err := combinatorics.Combinations(identities, uint(threshold))
		require.NoError(t, err)

		for _, cosignerIdentities := range combinations {
			cosigners := make([]*dkls_bbot_sign.Cosigner, len(cosignerIdentities))
			for i := range len(cosigners) {
				shard, ok := shards.Get(cosignerIdentities[i])
				require.True(t, ok)
				cosigners[i], err = dkls_bbot_sign.NewCosigner(sessionId, cosignerIdentities[i].(types.AuthKey), hashset.NewHashableHashSet[types.IdentityKey](cosignerIdentities...), shard, protocol, prng, tape.Clone())
				require.NoError(t, err)
			}

			r1bo := make([]*dkls_bbot_sign.Round1Broadcast, len(cosigners))
			r1uo := make([]network.RoundMessages[types.ThresholdSignatureProtocol, *dkls_bbot_sign.Round1P2P], len(cosigners))
			for i, cosigner := range cosigners {
				r1bo[i], r1uo[i], err = cosigner.Round1()
				require.NoError(t, err)
			}

			r2bi, r2ui := ttu.MapO2I(t, cosigners, r1bo, r1uo)
			r2bo := make([]*dkls_bbot_sign.Round2Broadcast, len(cosigners))
			r2uo := make([]network.RoundMessages[types.ThresholdSignatureProtocol, *dkls_bbot_sign.Round2P2P], len(cosigners))
			for i, cosigner := range cosigners {
				r2bo[i], r2uo[i], err = cosigner.Round2(r2bi[i], r2ui[i])
				require.NoError(t, err)
			}

			r3bi, r3ui := ttu.MapO2I(t, cosigners, r2bo, r2uo)
			r3bo := make([]*dkls_bbot_sign.Round3Broadcast, len(cosigners))
			r3uo := make([]network.RoundMessages[types.ThresholdSignatureProtocol, *dkls_bbot_sign.Round3P2P], len(cosigners))
			for i, cosigner := range cosigners {
				r3bo[i], r3uo[i], err = cosigner.Round3(r3bi[i], r3ui[i])
				require.NoError(t, err)
			}

			message := []byte("Hello World")
			r4bi, r4ui := ttu.MapO2I(t, cosigners, r3bo, r3uo)
			partialSignatures := network.NewRoundMessages[types.ThresholdSignatureProtocol, *dkls23.PartialSignature]()
			for i, cosigner := range cosigners {
				partialSignature, err := cosigner.Round4(r4bi[i], r4ui[i], message)
				require.NoError(t, err)
				partialSignatures.Put(cosignerIdentities[i], partialSignature)
			}

			pk := cosigners[0].MyShard.PublicKey()
			signature, err := signing.Aggregate(signingSuite, pk, partialSignatures, message)
			require.NoError(t, err)

			err = ecdsa.Verify(signature, signingSuite.Hash(), pk, message)
			require.NoError(t, err)

			tapeState := make([][]byte, len(cosigners))
			for i, cosigner := range cosigners {
				tapeState[i], err = cosigner.Tape.ExtractBytes("testtest", 32)
				require.NoError(t, err)
				if i > 0 {
					require.True(t, bytes.Equal(tapeState[i-1], tapeState[i]))
				}
			}
		}
	}
}
