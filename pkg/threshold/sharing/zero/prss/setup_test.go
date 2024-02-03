package prss_test

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
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/prss"
)

func Test_Setup(t *testing.T) {
	cipherSuite := &integration.CipherSuite{
		Curve: k256.NewCurve(),
		Hash:  sha256.New,
	}

	n := 5
	threshold := 3
	allIdentities, err := testutils.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	config, err := testutils.MakeCohortProtocol(cipherSuite, protocols.DKLS24, allIdentities, threshold, allIdentities)
	require.NoError(t, err)

	setupParticipants := make([]*prss.SetupParticipant, n)
	for i, identity := range allIdentities {
		setupParticipants[i], err = prss.NewSetupParticipant(identity.(integration.AuthKey), config, crand.Reader)
		require.NoError(t, err)
	}

	round1Outputs := make([]map[types.IdentityHash]*prss.Round1P2P, n)
	for i, participant := range setupParticipants {
		round1Outputs[i], err = participant.Round1()
		require.NoError(t, err)
	}

	round2Inputs := testutils.MapUnicastO2I(setupParticipants, round1Outputs)

	seeds := make([]*prss.Seed, n)
	for i, participant := range setupParticipants {
		seeds[i] = participant.Round2(round2Inputs[i])
	}

	sampleParticipants := make([]*prss.SampleParticipant, n)
	for i, identity := range allIdentities {
		sampleParticipants[i], err = prss.NewSampleParticipant(identity.(integration.AuthKey), config, seeds[i].Ra, crand.Reader)
		require.NoError(t, err)
	}

	samples := make([]curves.Scalar, n)
	for i, participant := range sampleParticipants {
		samples[i] = participant.Sample()
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

	for i := 0; i < len(secrets)-1; i++ {
		require.Zero(t, secrets[i].Cmp(secrets[i+1]))
	}
}
