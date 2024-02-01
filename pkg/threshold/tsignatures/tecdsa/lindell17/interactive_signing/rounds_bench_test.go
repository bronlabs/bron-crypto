package interactive_signing_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/interactive_signing"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/trusted_dealer"
)

func Benchmark_InteractiveSigning(b *testing.B) {
	cipherSuite := &integration.CipherSuite{
		Curve: k256.NewCurve(),
		Hash:  sha256.New,
	}
	sessionId := []byte("benchmarkSessionId")
	message := []byte("Hello World!")

	identities, err := testutils.MakeTestIdentities(cipherSuite, 3)
	require.NoError(b, err)
	alice, bob, charlie := identities[0], identities[1], identities[2]

	cohortConfig, err := testutils.MakeCohortProtocol(cipherSuite, protocols.LINDELL17, identities, lindell17.Threshold, []integration.IdentityKey{alice, bob, charlie})
	require.NoError(b, err)

	shards, err := trusted_dealer.Keygen(cohortConfig, crand.Reader)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		primary, err := interactive_signing.NewPrimaryCosigner(alice.(integration.AuthKey), bob, shards[alice.Hash()], cohortConfig, sessionId, nil, crand.Reader)
		require.NoError(b, err)
		secondary, err := interactive_signing.NewSecondaryCosigner(bob.(integration.AuthKey), alice, shards[bob.Hash()], cohortConfig, sessionId, nil, crand.Reader)
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
