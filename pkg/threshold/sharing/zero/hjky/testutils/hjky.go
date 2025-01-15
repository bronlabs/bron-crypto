package testutils

import (
	crand "crypto/rand"
	"io"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	ttu "github.com/bronlabs/krypton-primitives/pkg/base/types/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/network"
	randomisedFischlin "github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/zero/hjky"
)

var cn = randomisedFischlin.Name

func MakeParticipants(uniqueSessionId []byte, protocol types.ThresholdProtocol, identities []types.IdentityKey, prngs []io.Reader) (participants []*hjky.Participant, err error) {
	if len(identities) != int(protocol.TotalParties()) {
		return nil, errs.NewLength("invalid number of identities %d != %d", len(identities), protocol.TotalParties())
	}

	participants = make([]*hjky.Participant, protocol.TotalParties())
	for i, identity := range identities {
		var prng io.Reader
		if len(prngs) != 0 && prngs[i] != nil {
			prng = prngs[i]
		} else {
			prng = crand.Reader
		}

		if !protocol.Participants().Contains(identity) {
			return nil, errs.NewMissing("given test identity not in protocol config (problem in tests?)")
		}

		participants[i], err = hjky.NewParticipant(uniqueSessionId, identity.(types.AuthKey), protocol, cn, nil, prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct participant")
		}
	}

	return participants, nil
}

func DoRound1(participants []*hjky.Participant) (round1BroadcastOutputs []*hjky.Round1Broadcast, round1UnicastOutputs []network.RoundMessages[types.ThresholdProtocol, *hjky.Round1P2P], err error) {
	round1BroadcastOutputs = make([]*hjky.Round1Broadcast, len(participants))
	round1UnicastOutputs = make([]network.RoundMessages[types.ThresholdProtocol, *hjky.Round1P2P], len(participants))
	for i, participant := range participants {
		round1BroadcastOutputs[i], round1UnicastOutputs[i], err = participant.Round1()
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not run HJKY DKG round 1")
		}
	}

	return round1BroadcastOutputs, round1UnicastOutputs, nil
}

func DoDkgRound2(participants []*hjky.Participant, round2BroadcastInputs []network.RoundMessages[types.ThresholdProtocol, *hjky.Round1Broadcast], round2UnicastInputs []network.RoundMessages[types.ThresholdProtocol, *hjky.Round1P2P]) (samples []hjky.Sample, publicKeySharesMaps []ds.Map[types.SharingID, curves.Point], feldmanCommitmentVectors [][]curves.Point, err error) {
	samples = make([]hjky.Sample, len(participants))
	publicKeySharesMaps = make([]ds.Map[types.SharingID, curves.Point], len(participants))
	feldmanCommitmentVectors = make([][]curves.Point, len(participants))
	for i := range participants {
		samples[i], publicKeySharesMaps[i], feldmanCommitmentVectors[i], err = participants[i].Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
		if err != nil {
			return nil, nil, nil, errs.WrapFailed(err, "could not run HJKY DKG round 2")
		}
	}

	return samples, publicKeySharesMaps, feldmanCommitmentVectors, nil
}

func RunSample(t require.TestingT, sid []byte, protocol types.ThresholdProtocol, identities []types.IdentityKey) (participants []*hjky.Participant, samples []hjky.Sample, publicKeySharesMaps []ds.Map[types.SharingID, curves.Point], feldmanCommitmentVectors [][]curves.Point, err error) {
	participants, err = MakeParticipants(sid, protocol, identities, nil)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	r1OutsB, r1OutsU, err := DoRound1(participants)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	r2InsB, r2InsU := ttu.MapO2I(t, participants, r1OutsB, r1OutsU)
	samples, publicKeySharesMaps, feldmanCommitmentVectors, err = DoDkgRound2(participants, r2InsB, r2InsU)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return participants, samples, publicKeySharesMaps, feldmanCommitmentVectors, nil
}
