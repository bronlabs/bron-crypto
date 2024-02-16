package interactive_signing_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randomised_fischlin"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/interactive_signing"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/trusted_dealer"
)

func Benchmark_InteractiveSigning(b *testing.B) {
	cipherSuite, err := testutils.MakeSignatureProtocol(k256.NewCurve(), sha256.New)
	require.NoError(b, err)

	sessionId := []byte("benchmarkSessionId")
	message := []byte("Hello World!")

	identities, err := testutils.MakeTestIdentities(cipherSuite, 3)
	require.NoError(b, err)
	alice, bob, _ := identities[0], identities[1], identities[2]

	cohortConfig, err := testutils.MakeThresholdSignatureProtocol(cipherSuite, identities, 2, identities)
	require.NoError(b, err)

	shards, err := trusted_dealer.Keygen(cohortConfig, crand.Reader)
	require.NoError(b, err)
	aliceShard, _ := shards.Get(alice)
	bobShard, _ := shards.Get(bob)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {

		primary, err := interactive_signing.NewPrimaryCosigner(sessionId, alice.(types.AuthKey), bob, aliceShard, cohortConfig, randomisedFischlin.Name, nil, crand.Reader)
		require.NoError(b, err)
		secondary, err := interactive_signing.NewSecondaryCosigner(sessionId, bob.(types.AuthKey), alice, bobShard, cohortConfig, randomisedFischlin.Name, nil, crand.Reader)
		require.NoError(b, err)

		r1, err := primary.Round1()
		require.NoError(b, err)
		r2, err := secondary.Round2(r1)
		require.NoError(b, err)
		r3, err := primary.Round3(r2)
		require.NoError(b, err)
		r4, err := secondary.Round4(r3, message)
		require.NoError(b, err)
		_, err = primary.Round5(r4, message)
		require.NoError(b, err)
	}
}
