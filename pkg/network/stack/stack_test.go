package stack_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	typesTestutils "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack/testutils"
	fiatShamir "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/jf"
	jfTestutils "github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/jf/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

func runAgreeOnRandom(participant *agreeonrandom.Participant, comm stack.ProtocolClient) ([]byte, error) {
	const roundPrefixLabel = "AgreeOnRandomLabel"
	roundPrefixBytes, err := participant.Transcript.ExtractBytes(roundPrefixLabel, 16)
	if err != nil {
		return nil, err
	}
	round1 := fmt.Sprintf("%s_AgreeOnRandom_R1", hex.EncodeToString(roundPrefixBytes[:]))
	round2 := fmt.Sprintf("%s_AgreeOnRandom_R2", hex.EncodeToString(roundPrefixBytes[:]))

	coparties := participant.Protocol.Participants().Clone()
	coparties.Remove(participant.IdentityKey())

	// round 1
	r1bo, err := participant.Round1()
	if err != nil {
		return nil, err
	}
	stack.RoundSendBroadcastOnly(comm, round1, r1bo)

	// round 2
	r2bi := stack.RoundReceiveBroadcastOnly[*agreeonrandom.Round1Broadcast](comm, round1, coparties)
	r2bo, err := participant.Round2(r2bi)
	if err != nil {
		return nil, err
	}
	stack.RoundSendBroadcastOnly(comm, round2, r2bo)

	// round 3
	r3bi := stack.RoundReceiveBroadcastOnly[*agreeonrandom.Round2Broadcast](comm, round2, coparties)
	randomValue, err := participant.Round3(r3bi)
	if err != nil {
		return nil, err
	}

	return randomValue, nil
}

func runDkg(participant *jf.Participant, comm stack.ProtocolClient) (*tsignatures.SigningKeyShare, *tsignatures.PartialPublicKeys, error) {
	const roundPrefixLabel = "GennaroDKG"
	roundPrefixBytes, err := participant.Transcript.ExtractBytes(roundPrefixLabel, 16)
	if err != nil {
		return nil, nil, err
	}
	round1 := fmt.Sprintf("%s_GennaroDKG_R1", hex.EncodeToString(roundPrefixBytes[:]))
	round2 := fmt.Sprintf("%s_GennaroDKG_R2", hex.EncodeToString(roundPrefixBytes[:]))

	coparties := participant.Protocol.Participants().Clone()
	coparties.Remove(participant.IdentityKey())

	// Round 1
	r1bo, r1uo, err := participant.Round1()
	if err != nil {
		return nil, nil, err
	}
	stack.RoundSend(comm, round1, r1bo, r1uo)

	// Round 2
	r2bi, r2ui := stack.RoundReceive[*jf.Round1Broadcast, *jf.Round1P2P](comm, round1, coparties, coparties)
	r2bo, err := participant.Round2(r2bi, r2ui)
	if err != nil {
		return nil, nil, err
	}
	stack.RoundSendBroadcastOnly(comm, round2, r2bo)

	// Round 3
	r3bi := stack.RoundReceiveBroadcastOnly[*jf.Round2Broadcast](comm, round2, coparties)
	keyShare, partialPublicKeys, err := participant.Round3(r3bi)
	if err != nil {
		return nil, nil, err
	}

	return keyShare, partialPublicKeys, nil
}

func runCombined(i int, protocol types.ThresholdProtocol, transcript transcripts.Transcript, identities []types.IdentityKey, comm stack.ProtocolClient) (*tsignatures.SigningKeyShare, *tsignatures.PartialPublicKeys, error) {
	// Agree On Random
	aorParticipant, err := agreeonrandom.NewParticipant(identities[i].(types.AuthKey), protocol, transcript, crand.Reader)
	if err != nil {
		return nil, nil, err
	}
	randomNumber, err := runAgreeOnRandom(aorParticipant, comm)
	if err != nil {
		return nil, nil, err
	}

	// DKG
	dkgParticipant, err := jf.NewParticipant(randomNumber, identities[i].(types.AuthKey), protocol, fiatShamir.Name, crand.Reader, transcript)
	if err != nil {
		return nil, nil, err
	}
	signingKeyShare, publicKeyShare, err := runDkg(dkgParticipant, comm)
	if err != nil {
		return nil, nil, err
	}

	return signingKeyShare, publicKeyShare, nil
}

func Test_HappyPathDkg(t *testing.T) {
	t.Parallel()

	const n = 3
	const threshold = 2
	const niCompilerName = fiatShamir.Name
	curve := edwards25519.NewCurve()
	sessionId := "LoremIpsum12345678_Test"

	identities := make([]types.IdentityKey, 3)
	for i := range identities {
		sk, err := p256.NewCurve().ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		identities[i] = testutils.NewTestAuthKey(sk)
	}

	protocol, err := typesTestutils.MakeThresholdProtocol(curve, identities, threshold)
	require.NoError(t, err)

	participants, err := jfTestutils.MakeParticipants(t, []byte(sessionId), protocol, identities, niCompilerName, nil)
	require.NoError(t, err)

	communicationStack := testutils.NewSimulatorStack()
	signingKeyShares := make([]*tsignatures.SigningKeyShare, n)
	partialPublicKeys := make([]*tsignatures.PartialPublicKeys, n)

	var eg errgroup.Group
	for i := range n {
		eg.Go(func() error {
			var err error
			comm := communicationStack.Dial([]byte(sessionId), identities[i].(types.AuthKey), protocol)
			signingKeyShares[i], partialPublicKeys[i], err = runDkg(participants[i], comm)
			return err
		})
	}
	err = eg.Wait()
	require.NoError(t, err)

	t.Run("each signing key share is different than all others", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < len(signingKeyShares); i++ {
			for j := i + 1; j < len(signingKeyShares); j++ {
				require.NotZero(t, signingKeyShares[i].Share.Cmp(signingKeyShares[j].Share))
			}
		}
	})

	t.Run("each public key is the same as all others", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < len(signingKeyShares); i++ {
			for j := i + 1; j < len(signingKeyShares); j++ {
				require.True(t, signingKeyShares[i].PublicKey.Equal(signingKeyShares[j].PublicKey))
			}
		}
	})

	t.Run("reconstructed private key is the dlog of the public key", func(t *testing.T) {
		t.Parallel()
		shamirDealer, err := shamir.NewDealer(uint(threshold), uint(n), curve)
		require.NoError(t, err)
		require.NotNil(t, shamirDealer)
		shamirShares := make([]*shamir.Share, len(participants))
		for i := 0; i < len(participants); i++ {
			shamirShares[i] = &shamir.Share{
				Id:    uint(participants[i].SharingId()),
				Value: signingKeyShares[i].Share,
			}
		}

		reconstructedPrivateKey, err := shamirDealer.Combine(shamirShares...)
		require.NoError(t, err)

		derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)
		require.True(t, signingKeyShares[0].PublicKey.Equal(derivedPublicKey))
	})
}

func Test_RunAoRAndDKG(t *testing.T) {
	t.Parallel()

	const n = 3
	const threshold = 2
	curve := edwards25519.NewCurve()
	sessionId := []byte("LoremIpsum12345678_Test")

	identities := make([]types.IdentityKey, n)
	for i := range identities {
		sk, err := p256.NewCurve().ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		identities[i] = testutils.NewTestAuthKey(sk)
	}

	sharingCfg := types.DeriveSharingConfig(hashset.NewComparableHashSet[types.IdentityKey](identities...))
	sharingIds := make([]types.SharingID, n)
	for i := range sharingIds {
		var ok bool
		sharingIds[i], ok = sharingCfg.Reverse().Get(identities[i])
		require.True(t, ok)
	}

	protocol, err := typesTestutils.MakeThresholdProtocol(curve, identities, threshold)
	require.NoError(t, err)

	trans := make([]transcripts.Transcript, n)
	for i := range trans {
		trans[i] = hagrid.NewTranscript(string(sessionId), nil)
	}

	communicationStack := testutils.NewSimulatorStack()
	signingKeyShares := make([]*tsignatures.SigningKeyShare, n)
	partialPublicKeys := make([]*tsignatures.PartialPublicKeys, n)

	var eg errgroup.Group
	for i := range n {
		eg.Go(func() error {
			var err error
			comm := communicationStack.Dial(sessionId, identities[i].(types.AuthKey), protocol)
			signingKeyShares[i], partialPublicKeys[i], err = runCombined(i, protocol, trans[i], identities, comm)
			return err
		})
	}
	err = eg.Wait()
	require.NoError(t, err)

	t.Run("each signing key share is different than all others", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < len(signingKeyShares); i++ {
			for j := i + 1; j < len(signingKeyShares); j++ {
				require.NotZero(t, signingKeyShares[i].Share.Cmp(signingKeyShares[j].Share))
			}
		}
	})

	t.Run("each public key is the same as all others", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < len(signingKeyShares); i++ {
			for j := i + 1; j < len(signingKeyShares); j++ {
				require.True(t, signingKeyShares[i].PublicKey.Equal(signingKeyShares[j].PublicKey))
			}
		}
	})

	t.Run("reconstructed private key is the dlog of the public key", func(t *testing.T) {
		t.Parallel()
		shamirDealer, err := shamir.NewDealer(uint(threshold), uint(n), curve)
		require.NoError(t, err)
		require.NotNil(t, shamirDealer)
		shamirShares := make([]*shamir.Share, len(sharingIds))
		for i := 0; i < len(sharingIds); i++ {
			shamirShares[i] = &shamir.Share{
				Id:    uint(sharingIds[i]),
				Value: signingKeyShares[i].Share,
			}
		}

		reconstructedPrivateKey, err := shamirDealer.Combine(shamirShares...)
		require.NoError(t, err)

		derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)
		require.True(t, signingKeyShares[0].PublicKey.Equal(derivedPublicKey))
	})
}
