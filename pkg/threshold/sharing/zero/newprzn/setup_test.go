package newprzn_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/newprzn"
	"github.com/stretchr/testify/require"
	"gonum.org/v1/gonum/stat/combin"
	"testing"
)

func Test_HappyPath(t *testing.T) {
	cipherSuite := &integration.CipherSuite{
		Curve: k256.NewCurve(),
		Hash:  sha256.New,
	}

	n := 5
	threshold := 3
	allIdentities, err := testutils.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	setupParticipants := make([]*newprzn.SetupParticipant, n)
	for i, identity := range allIdentities {
		setupParticipants[i], err = newprzn.NewSetupParticipant(cipherSuite.Curve.ScalarField(), identity, hashset.NewHashSet(allIdentities), threshold, crand.Reader)
		require.NoError(t, err)
	}

	round1Outputs := make([]map[types.IdentityHash]*newprzn.Round1P2P, n)
	for i, participant := range setupParticipants {
		round1Outputs[i], err = participant.Round1()
		require.NoError(t, err)
	}

	round2Inputs := testutils.MapUnicastO2I(setupParticipants, round1Outputs)

	results := make([]map[int]curves.Scalar, n)
	for i, participant := range setupParticipants {
		results[i] = participant.Round2(round2Inputs[i])
	}

	sampleParticipants := make([]*newprzn.SampleParticipant, n)
	for i, identity := range allIdentities {
		sampleParticipants[i], err = newprzn.NewSampleParticipant(identity, hashset.NewHashSet(allIdentities), threshold, results[i], crand.Reader)
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
		dealer, err := shamir.NewDealer(threshold, n, k256.NewCurve())
		require.NoError(t, err)
		secret, err := dealer.Combine(shares...)
		require.NoError(t, err)
		secrets = append(secrets, secret)
	}

	for i := 0; i < len(secrets)-1; i++ {
		require.Zero(t, secrets[i], secrets[i+1])
	}
}
