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
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/prss"
)

func Test_RandomSample(t *testing.T) {
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

	//setupParticipants := make([]*newprzn.SetupParticipant, n)
	//for i, identity := range allIdentities {
	//	setupParticipants[i], err = newprzn.NewSetupParticipant(cipherSuite.Curve.ScalarField(), identity, hashset.NewHashSet(allIdentities), t, crand.Reader)
	//	require.NoError(t, err)
	//}
	//
	//round1Outputs := make([]map[types.IdentityHash]*newprzn.Round1P2P, n)
	//for i, participant := range setupParticipants {
	//	round1Outputs[i], err = participant.Round1()
	//	require.NoError(t, err)
	//}
	//
	//round2Inputs := testutils.MapUnicastO2I(setupParticipants, round1Outputs)
	//
	//results := make([]map[int]curves.Scalar, n)
	//for i, participant := range setupParticipants {
	//	results[i] = participant.Round2(round2Inputs[i])
	//}

	seeds, err := prss.Deal(config, crand.Reader)
	require.NoError(t, err)

	sampleParticipants := make([]*prss.SampleParticipant, n)
	for i, identity := range allIdentities {
		sampleParticipants[i], err = prss.NewSampleParticipant(identity.(integration.AuthKey), config, seeds[identity.Hash()].Ra, crand.Reader)
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

func Test_ZeroSample(t *testing.T) {
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

	seeds, err := prss.Deal(config, crand.Reader)
	require.NoError(t, err)

	sampleParticipants := make([]*prss.SampleParticipant, n)
	for i, identity := range allIdentities {
		sampleParticipants[i], err = prss.NewSampleParticipant(identity.(integration.AuthKey), config, seeds[identity.Hash()].Ra, crand.Reader)
		require.NoError(t, err)
	}

	samples := make([]curves.Scalar, n)
	for i, participant := range sampleParticipants {
		samples[i] = participant.SampleZero()
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
