package testutils

import (
	crand "crypto/rand"
	"github.com/stretchr/testify/require"
	"io"

	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	ttu "github.com/bronlabs/krypton-primitives/pkg/base/types/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/network"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler"
	randomisedFischlin "github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/dkg/jf"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures"
)

func MakeParticipants(t require.TestingT, uniqueSessionId []byte, protocol types.ThresholdProtocol, identities []types.IdentityKey, niCompilerName compiler.Name, prngs []io.Reader) (participants []*jf.Participant, err error) {
	if len(identities) != int(protocol.TotalParties()) {
		return nil, errs.NewLength("invalid number of identities %d != %d", len(identities), protocol.TotalParties())
	}

	participants = make([]*jf.Participant, protocol.TotalParties())
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
		participants[i], err = jf.NewParticipant(uniqueSessionId, identity.(types.AuthKey), protocol, niCompilerName, prng, nil)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct participant")
		}
	}

	return participants, nil
}

func DoDkgRound1(t require.TestingT, participants []*jf.Participant) (round1BroadcastOutputs []*jf.Round1Broadcast, round1UnicastOutputs []network.RoundMessages[types.ThresholdProtocol, *jf.Round1P2P], err error) {
	round1BroadcastOutputs = make([]*jf.Round1Broadcast, len(participants))
	round1UnicastOutputs = make([]network.RoundMessages[types.ThresholdProtocol, *jf.Round1P2P], len(participants))
	for i := range participants {
		round1BroadcastOutputs[i], round1UnicastOutputs[i], err = participants[i].Round1()
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "%s could not run JF round 1", participants[i].IdentityKey().String())
		}
	}

	return round1BroadcastOutputs, round1UnicastOutputs, nil
}

func DoDkgRound2(t require.TestingT, participants []*jf.Participant, round2BroadcastInputs []network.RoundMessages[types.ThresholdProtocol, *jf.Round1Broadcast], round2UnicastInputs []network.RoundMessages[types.ThresholdProtocol, *jf.Round1P2P]) (round2Outputs []*jf.Round2Broadcast, err error) {
	round2Outputs = make([]*jf.Round2Broadcast, len(participants))
	for i := range participants {
		round2Outputs[i], err = participants[i].Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "%s could not run JF round 2", participants[i].IdentityKey().String())
		}
	}
	return round2Outputs, nil
}

func DoDkgRound3(t require.TestingT, participants []*jf.Participant, round3Inputs []network.RoundMessages[types.ThresholdProtocol, *jf.Round2Broadcast]) (signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PartialPublicKeys, err error) {
	signingKeyShares = make([]*tsignatures.SigningKeyShare, len(participants))
	publicKeyShares = make([]*tsignatures.PartialPublicKeys, len(participants))
	for i := range participants {
		signingKeyShares[i], publicKeyShares[i], err = participants[i].Round3(round3Inputs[i])
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "%s could not run JF round 3", participants[i].IdentityKey().String())
		}
	}

	return signingKeyShares, publicKeyShares, nil
}

func DoDkg(t require.TestingT, uniqueSessionId []byte, protocol types.ThresholdProtocol, identities []types.IdentityKey) (signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PartialPublicKeys, err error) {
	participants, err := MakeParticipants(t, uniqueSessionId, protocol, identities, randomisedFischlin.Name, nil)
	if err != nil {
		return nil, nil, err
	}

	r1OutsB, r1OutsU, err := DoDkgRound1(t, participants)
	if err != nil {
		return nil, nil, err
	}

	r2InsB, r2InsU := ttu.MapO2I(t, participants, r1OutsB, r1OutsU)
	r2OutsB, err := DoDkgRound2(t, participants, r2InsB, r2InsU)
	if err != nil {
		return nil, nil, err
	}

	r3InsB := ttu.MapBroadcastO2I(t, participants, r2OutsB)
	signingKeyShares, publicKeyShares, err = DoDkgRound3(t, participants, r3InsB)
	if err != nil {
		return nil, nil, err
	}
	return signingKeyShares, publicKeyShares, nil
}

func DoDkgHappyPath(t require.TestingT, uniqueSessionId []byte, protocol types.ThresholdProtocol, identities []types.IdentityKey) (signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PartialPublicKeys) {
	signingKeyShares, publicKeyShares, err := DoDkg(t, uniqueSessionId, protocol, identities)
	require.NoError(t, err)
	return signingKeyShares, publicKeyShares
}
