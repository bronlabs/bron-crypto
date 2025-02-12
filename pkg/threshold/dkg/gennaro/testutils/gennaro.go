package testutils

import (
	crand "crypto/rand"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	ttu "github.com/bronlabs/krypton-primitives/pkg/base/types/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/network"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/dkg/gennaro"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts"
	"github.com/stretchr/testify/require"
	"io"
	"testing"
)

func MakeGennaroParticipants(sessionId []byte, protocol types.ThresholdProtocol, identities []types.IdentityKey, tapes []transcripts.Transcript, prngs []io.Reader) (participants []*gennaro.Participant, err error) {
	if len(identities) != int(protocol.TotalParties()) {
		return nil, errs.NewLength("invalid number of identities %d != %d", len(identities), protocol.TotalParties())
	}

	participants = make([]*gennaro.Participant, protocol.TotalParties())
	for i, identity := range identities {
		var prng io.Reader
		if len(prngs) != 0 && prngs[i] != nil {
			prng = prngs[i]
		} else {
			prng = crand.Reader
		}

		if !protocol.Participants().Contains(identity) {
			return nil, errs.NewMissing("given test identity not a participant (problem in tests?)")
		}

		participants[i], err = gennaro.NewParticipant(sessionId, identity.(types.AuthKey), protocol, tapes[i], prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct participant")
		}
	}

	return participants, nil
}

func DoGennaroRound1(participants []*gennaro.Participant) (round1BroadcastOutputs []*gennaro.Round1Broadcast, err error) {
	round1BroadcastOutputs = make([]*gennaro.Round1Broadcast, len(participants))
	for i := range participants {
		round1BroadcastOutputs[i], err = participants[i].Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "%s could not run Gennaro round 1", participants[i].IdentityKey().String())
		}
	}

	return round1BroadcastOutputs, nil
}

func DoGennaroRound2(participants []*gennaro.Participant, round2BroadcastInputs []network.RoundMessages[types.ThresholdProtocol, *gennaro.Round1Broadcast]) (round2BroadcastOutputs []*gennaro.Round2Broadcast, round2UnicastOutputs []network.RoundMessages[types.ThresholdProtocol, *gennaro.Round2P2P], err error) {
	round2BroadcastOutputs = make([]*gennaro.Round2Broadcast, len(participants))
	round2UnicastOutputs = make([]network.RoundMessages[types.ThresholdProtocol, *gennaro.Round2P2P], len(participants))
	for i := range participants {
		round2BroadcastOutputs[i], round2UnicastOutputs[i], err = participants[i].Round2(round2BroadcastInputs[i])
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "%s could not run Gennaro round 2", participants[i].IdentityKey().String())
		}
	}
	return round2BroadcastOutputs, round2UnicastOutputs, nil
}

func DoGennaroRound3(participants []*gennaro.Participant, round3BroadcastInputs []network.RoundMessages[types.ThresholdProtocol, *gennaro.Round2Broadcast], round3UnicastInputs []network.RoundMessages[types.ThresholdProtocol, *gennaro.Round2P2P]) (signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PartialPublicKeys, err error) {
	signingKeyShares = make([]*tsignatures.SigningKeyShare, len(participants))
	publicKeyShares = make([]*tsignatures.PartialPublicKeys, len(participants))
	for i := range participants {
		signingKeyShares[i], publicKeyShares[i], err = participants[i].Round3(round3BroadcastInputs[i], round3UnicastInputs[i])
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "%s could not run Gennaro round 3", participants[i].IdentityKey().String())
		}
	}

	return signingKeyShares, publicKeyShares, nil
}

func DoGennaroDkg(tb testing.TB, sessionId []byte, protocol types.ThresholdProtocol, identities []types.IdentityKey, tapes []transcripts.Transcript) (signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PartialPublicKeys, err error) {
	tb.Helper()

	participants, err := MakeGennaroParticipants(sessionId, protocol, identities, tapes, nil)
	if err != nil {
		return nil, nil, err
	}

	r1OutsB, err := DoGennaroRound1(participants)
	if err != nil {
		return nil, nil, err
	}

	r2InsB := ttu.MapBroadcastO2I(tb, participants, r1OutsB)
	r2OutsB, r2OutsU, err := DoGennaroRound2(participants, r2InsB)
	if err != nil {
		return nil, nil, err
	}

	r3InsB, r3InsU := ttu.MapO2I(tb, participants, r2OutsB, r2OutsU)
	signingKeyShares, publicKeyShares, err = DoGennaroRound3(participants, r3InsB, r3InsU)
	if err != nil {
		return nil, nil, err
	}
	return signingKeyShares, publicKeyShares, nil
}

func DoDkgHappyPath(tb testing.TB, sessionId []byte, protocol types.ThresholdProtocol, identities []types.IdentityKey, tapes []transcripts.Transcript) (signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PartialPublicKeys) {
	tb.Helper()

	signingKeyShares, publicKeyShares, err := DoGennaroDkg(tb, sessionId, protocol, identities, tapes)
	require.NoError(tb, err)
	return signingKeyShares, publicKeyShares
}
