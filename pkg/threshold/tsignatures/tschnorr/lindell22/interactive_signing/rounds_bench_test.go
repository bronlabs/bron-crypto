package interactive_signing_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integrationTestutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/interactive_signing/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/keygen/trusted_dealer"
)

func Benchmark_InteractiveSigning(b *testing.B) {
	hashFunc := sha512.New
	curve := edwards25519.NewCurve()
	prng := crand.Reader
	message := []byte("Hello World!")
	th := 2
	n := 3
	sid := []byte("benchmarkSessionId")

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  hashFunc,
	}

	identities, err := integrationTestutils.MakeTestIdentities(cipherSuite, n)
	require.NoError(b, err)

	cohort, err := integrationTestutils.MakeCohortProtocol(cipherSuite, protocols.LINDELL22, identities, th, identities)
	require.NoError(b, err)

	shards, err := trusted_dealer.Keygen(cohort, prng)
	require.NoError(b, err)

	transcripts := integrationTestutils.MakeTranscripts("Lindell 2022 Interactive Sign", identities)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		participants, err := testutils.MakeParticipants(sid, cohort, identities[:th], shards, transcripts, false)
		require.NoError(b, err)
		_, err = testutils.RunInteractiveSigning(participants, message)
		require.NoError(b, err)
	}
}
