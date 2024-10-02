package stack_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	typesTestutils "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack/testutils"
	fiatShamir "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/jf"
	jfTestutils "github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/jf/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
)

func runDkg(participant *jf.Participant, communicationStack stack.Stack) (*tsignatures.SigningKeyShare, *tsignatures.PartialPublicKeys, error) {
	const ROUND1 string = "r1"
	const ROUND2 string = "r2"

	communicationClient := communicationStack.Dial(participant.IdentityKey().(types.AuthKey), participant.Protocol)

	coparties := participant.Protocol.Participants().Clone()
	coparties.Remove(participant.IdentityKey())

	// Round 1
	r1bo, r1uo, err := participant.Round1()
	if err != nil {
		return nil, nil, err
	}
	stack.RoundSend(communicationClient, ROUND1, r1bo, r1uo)

	// Round 2
	r2bi, r2ui := stack.RoundReceive[*jf.Round1Broadcast, *jf.Round1P2P](communicationClient, ROUND1, coparties, coparties)
	r2bo, err := participant.Round2(r2bi, r2ui)
	if err != nil {
		return nil, nil, err
	}
	stack.RoundSendBroadcastOnly(communicationClient, ROUND2, r2bo)

	// Round 3
	r3bi := stack.RoundReceiveBroadcastOnly[*jf.Round2Broadcast](communicationClient, ROUND2, coparties)
	keyShare, partialPublicKeys, err := participant.Round3(r3bi)
	if err != nil {
		return nil, nil, err
	}

	return keyShare, partialPublicKeys, nil
}

func Test_HappyPathDkg(t *testing.T) {
	t.Parallel()

	const n = 3
	const threshold = 2
	const niCompilerName = fiatShamir.Name
	curve := edwards25519.NewCurve()
	sessionId := []byte("LoremIpsum12345678_Test")

	identities := make([]types.IdentityKey, 3)
	for i := range identities {
		sk, err := p256.NewCurve().ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		identities[i] = testutils.NewTestAuthKey(sk)
	}

	protocol, err := typesTestutils.MakeThresholdProtocol(curve, identities, threshold)
	require.NoError(t, err)

	participants, err := jfTestutils.MakeParticipants(t, sessionId, protocol, identities, niCompilerName, nil)
	require.NoError(t, err)

	communicationStack := testutils.NewSimulatorStack()
	signingKeyShares := make([]*tsignatures.SigningKeyShare, n)
	partialPublicKeys := make([]*tsignatures.PartialPublicKeys, n)

	var eg errgroup.Group
	for i := range n {
		eg.Go(func() error {
			var err error
			signingKeyShares[i], partialPublicKeys[i], err = runDkg(participants[i], communicationStack)
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
