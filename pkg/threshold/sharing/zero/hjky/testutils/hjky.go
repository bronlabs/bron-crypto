package testutils

import (
	crand "crypto/rand"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	ttu "github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/hjky"
)

func MakeParticipants(sessionId []byte, protocol types.ThresholdProtocol, identities []types.IdentityKey, tapes []transcripts.Transcript, prngs []io.Reader) (participants []*hjky.Participant, err error) {
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

		participants[i], err = hjky.NewParticipant(sessionId, identity.(types.AuthKey), protocol, tapes[i], prng)
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

func DoRound2(participants []*hjky.Participant, round2BroadcastInputs []network.RoundMessages[types.ThresholdProtocol, *hjky.Round1Broadcast], round2UnicastInputs []network.RoundMessages[types.ThresholdProtocol, *hjky.Round1P2P]) (zeroShares []curves.Scalar, publicKeySharesMaps []ds.Map[types.SharingID, curves.Point], feldmanCommitmentVectors [][]curves.Point, err error) {
	zeroShares = make([]curves.Scalar, len(participants))
	publicKeySharesMaps = make([]ds.Map[types.SharingID, curves.Point], len(participants))
	feldmanCommitmentVectors = make([][]curves.Point, len(participants))
	for i := range participants {
		zeroShares[i], publicKeySharesMaps[i], feldmanCommitmentVectors[i], err = participants[i].Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
		if err != nil {
			return nil, nil, nil, errs.WrapFailed(err, "could not run HJKY DKG round 2")
		}
	}

	return zeroShares, publicKeySharesMaps, feldmanCommitmentVectors, nil
}

func DoRun(tb testing.TB, sid []byte, protocol types.ThresholdProtocol, identities []types.IdentityKey, tapes []transcripts.Transcript) (participants []*hjky.Participant, shares []curves.Scalar, publicKeySharesMaps []ds.Map[types.SharingID, curves.Point], feldmanCommitmentVectors [][]curves.Point, err error) {
	participants, err = MakeParticipants(sid, protocol, identities, tapes, nil)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	r1OutsB, r1OutsU, err := DoRound1(participants)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	r2InsB, r2InsU := ttu.MapO2I(tb, participants, r1OutsB, r1OutsU)
	shares, publicKeySharesMaps, feldmanCommitmentVectors, err = DoRound2(participants, r2InsB, r2InsU)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return participants, shares, publicKeySharesMaps, feldmanCommitmentVectors, nil
}
