package newprzs_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
	"gonum.org/v1/gonum/stat/combin"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/chacha20"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/newprzs"
)

func Test_Sample(t *testing.T) {
	n := 8
	threshold := 3
	cipherSuite := &integration.CipherSuite{
		Curve: k256.NewCurve(),
		Hash:  sha256.New,
	}
	sessionId := []byte("testSessionId")
	seededPrngFactory, err := chacha20.NewChachaPRNG(nil, nil)
	require.NoError(t, err)

	identities, err := testutils.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	cohortConfig, err := testutils.MakeCohortProtocol(cipherSuite, protocols.DKLS24, identities, threshold, identities)
	require.NoError(t, err)

	setupParticipants := make([]*newprzs.SetupParticipant, n)
	for i, identity := range identities {
		setupParticipants[i] = newprzs.NewSetupParticipant(identity.(integration.AuthKey), cohortConfig, crand.Reader)
	}

	r1Output := make([]map[types.IdentityHash]*newprzs.Round1P2P, n)
	for i, participant := range setupParticipants {
		r1Output[i], err = participant.Round1()
		require.NoError(t, err)
	}

	r2Input := testutils.MapUnicastO2I(setupParticipants, r1Output)
	seeds := make([]*newprzs.Seed, n)
	for i, participant := range setupParticipants {
		seeds[i], err = participant.Round2(r2Input[i])
		require.NoError(t, err)
	}

	sampleParticipants := make([]*newprzs.SampleParticipant, n)
	for i, identity := range identities {
		sampleParticipants[i], err = newprzs.NewSampleParticipant(sessionId, identity.(integration.AuthKey), cohortConfig, seeds[i], seededPrngFactory)
		require.NoError(t, err)
	}

	samples := make([]curves.Scalar, n)
	for i, participant := range sampleParticipants {
		samples[i], err = participant.Sample()
		require.NoError(t, err)
		require.False(t, samples[i].IsZero())
	}

	combinations := combin.Combinations(n, threshold)
	secrets := make([]curves.Scalar, 0)
	for _, combination := range combinations {
		shares := make([]*shamir.Share, len(combination))
		for i, c := range combination {
			shares[i] = &shamir.Share{
				Id:    sampleParticipants[c].GetSharingId(),
				Value: samples[c],
			}
		}
		dealer, err := shamir.NewDealer(threshold, n, cipherSuite.Curve)
		require.NoError(t, err)
		secret, err := dealer.Combine(shares...)
		require.NoError(t, err)
		secrets = append(secrets, secret)
	}

	for i := 0; i < len(secrets); i++ {
		require.True(t, secrets[i].IsZero())
	}
}
