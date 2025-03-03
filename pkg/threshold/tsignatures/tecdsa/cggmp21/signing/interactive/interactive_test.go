package interactive_signing_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256"
	"github.com/bronlabs/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/base/types/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/network"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/ecdsa"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tecdsa/cggmp21"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tecdsa/cggmp21/keygen/trusted_dealer"
	interactive_signing "github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tecdsa/cggmp21/signing/interactive"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	k256.RegisterForGob()

	const threshold = 3
	const total = 5
	prng := crand.Reader

	curve := k256.NewCurve()
	hashFunc := sha256.New
	message := "Hello World"
	rawShards, err := trusted_dealer.KeyGen(threshold, total, curve, prng)
	require.NoError(t, err)
	_shard, ok := rawShards.Get(1)
	require.True(t, ok)
	publicKey := _shard.Share.PublicKey

	identities, err := testutils.MakeDeterministicTestIdentities(total)
	require.NoError(t, err)

	suite, err := testutils.MakeSigningSuite(curve, hashFunc)
	require.NoError(t, err)
	protocol, err := testutils.MakeThresholdSignatureProtocol(suite, identities, threshold, identities)
	require.NoError(t, err)
	quorum := identities[:threshold]
	sharingCfg := types.DeriveSharingConfig(hashset.NewHashableHashSet[types.IdentityKey](identities...))
	shards := make([]*cggmp21.Shard, len(quorum))
	for i, id := range quorum {
		sharingId, ok := sharingCfg.Reverse().Get(id)
		require.True(t, ok)
		shards[i], ok = rawShards.Get(sharingId)
		require.True(t, ok)
	}

	participants := make([]*interactive_signing.Cosigner, len(quorum))
	for i := range participants {
		participants[i], err = interactive_signing.NewCosigner(quorum[i].(types.AuthKey), protocol, hashset.NewHashableHashSet[types.IdentityKey](quorum...), shards[i], prng)
		require.NoError(t, err)
	}

	r1OutB := make([]*interactive_signing.Round1Broadcast, len(participants))
	for i, participant := range participants {
		r1OutB[i], err = participant.Round1()
		require.NoError(t, err)
	}

	r2InB := testutils.MapBroadcastO2I(t, participants, r1OutB)
	r2OutB := make([]*interactive_signing.Round2Broadcast, len(participants))
	r2OutU := make([]network.RoundMessages[types.ThresholdSignatureProtocol, *interactive_signing.Round2P2P], len(participants))
	for i, participant := range participants {
		r2OutB[i], r2OutU[i], err = participant.Round2(r2InB[i])
		require.NoError(t, err)
	}

	r3InB, r3InU := testutils.MapO2I(t, participants, r2OutB, r2OutU)
	r3OutB := make([]*interactive_signing.Round3Broadcast, len(participants))
	for i, participant := range participants {
		r3OutB[i], err = participant.Round3(r3InB[i], r3InU[i])
		require.NoError(t, err)
	}

	r4InB := testutils.MapBroadcastO2I(t, participants, r3OutB)
	partialSignatures := make([]*cggmp21.PartialSignature, len(participants))
	for i, participant := range participants {
		partialSignatures[i], err = participant.Round4(r4InB[i], []byte(message))
		require.NoError(t, err)
	}

	signature, err := cggmp21.Aggregate(partialSignatures...)
	require.NoError(t, err)
	require.NotNil(t, signature)

	err = ecdsa.Verify(signature, hashFunc, publicKey, []byte(message))
	require.NoError(t, err)
}
