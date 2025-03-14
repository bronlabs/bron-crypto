package noninteractive_signing_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	ttu "github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/lindell17"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/trusted_dealer"
	noninteractive_signing "github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/lindell17/signing/noninteractive"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/lindell17/signing/noninteractive/testutils"
)

func Test_NonInteractiveSignHappyPath(t *testing.T) {
	t.Parallel()

	sid := []byte("sessionId")
	n := 3
	prng := crand.Reader
	transcriptAppLabel := "Lindell2017NonInteractiveSignTest"

	supportedCurves := []curves.Curve{
		p256.NewCurve(),
		k256.NewCurve(),
	}

	for _, c := range supportedCurves {
		curve := c
		t.Run(fmt.Sprintf("Lindell 2017 for %s", curve.Name()), func(t *testing.T) {
			t.Parallel()

			hash := sha256.New
			cipherSuite, err := ttu.MakeSigningSuite(curve, hash)
			require.NoError(t, err)

			identities, err := ttu.MakeTestIdentities(cipherSuite, n)
			require.NoError(t, err)

			protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, lindell17.Threshold, identities)
			require.NoError(t, err)

			message := []byte("Hello World!")
			require.NoError(t, err)

			shards, err := trusted_dealer.Keygen(protocol, crand.Reader)
			require.NoError(t, err)
			require.NotNil(t, shards)
			require.Equal(t, shards.Size(), int(protocol.TotalParties()))

			transcripts := testutils.MakeTranscripts(transcriptAppLabel, identities)
			participants := testutils.MakePreGenParticipants(t, identities, sid, protocol, transcripts)
			ppms := testutils.DoLindell2017PreGen(t, participants)
			require.NotNil(t, ppms)

			aliceIdx := 0
			bobIdx := 1

			aliceShard, exists := shards.Get(identities[aliceIdx])
			require.True(t, exists)
			alice, err := noninteractive_signing.NewCosigner(protocol, identities[aliceIdx].(types.AuthKey), aliceShard, ppms[aliceIdx], identities[aliceIdx], identities[bobIdx], prng)
			require.NoError(t, err)

			bobShard, exists := shards.Get(identities[bobIdx])
			require.True(t, exists)
			bob, err := noninteractive_signing.NewCosigner(protocol, identities[bobIdx].(types.AuthKey), bobShard, ppms[bobIdx], identities[aliceIdx], identities[bobIdx], prng)
			require.NoError(t, err)

			partialSignature, err := alice.ProducePartialSignature(message)
			require.NoError(t, err)

			signature, err := bob.ProduceSignature(ttu.GobRoundTrip(t, partialSignature), message)
			require.NoError(t, err)

			// signature is valid
			for _, identity := range identities {
				thisShard, exists := shards.Get(identity)
				require.True(t, exists)
				err := ecdsa.Verify(signature, cipherSuite.Hash(), thisShard.SigningKeyShare.PublicKey, message)
				require.NoError(t, err)
			}
		})
	}
}
