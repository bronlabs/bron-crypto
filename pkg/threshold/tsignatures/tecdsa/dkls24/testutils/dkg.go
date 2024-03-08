package testutils

import (
	crand "crypto/rand"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
	agreeonrandomTestutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	jf_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/jf/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/keygen/dkg"
)

var cn = randomisedFischlin.Name

func MakeDkgParticipants(curve curves.Curve, protocol types.ThresholdProtocol, identities []types.IdentityKey, signingKeyShares []*tsignatures.SigningKeyShare, partialPublicKeys []*tsignatures.PartialPublicKeys, prngs []io.Reader, sid []byte) (participants []*dkg.Participant, err error) {
	if len(identities) != int(protocol.TotalParties()) {
		return nil, errs.NewLength("invalid number of identities %d != %d", len(identities), protocol.TotalParties())
	}

	participants = make([]*dkg.Participant, protocol.TotalParties())

	if len(sid) == 0 {
		sid, err = agreeonrandomTestutils.RunAgreeOnRandom(curve, identities, crand.Reader)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct sid")
		}
	}

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

		participants[i], err = dkg.NewParticipant(sid, identity.(types.AuthKey), signingKeyShares[i], partialPublicKeys[i], protocol, cn, prng, nil)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct participant")
		}
	}

	return participants, nil
}

func DoDkgRound1(participants []*dkg.Participant) (round1UnicastOutputs []types.RoundMessages[*dkg.Round1P2P], err error) {
	round1UnicastOutputs = make([]types.RoundMessages[*dkg.Round1P2P], len(participants))
	for i, participant := range participants {
		round1UnicastOutputs[i], err = participant.Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run DKG round 1")
		}
	}

	return round1UnicastOutputs, nil
}

func DoDkgRound2(participants []*dkg.Participant, round2UnicastInputs []types.RoundMessages[*dkg.Round1P2P]) (round2UnicastOutputs []types.RoundMessages[*dkg.Round2P2P], err error) {
	round2UnicastOutputs = make([]types.RoundMessages[*dkg.Round2P2P], len(participants))
	for i := range participants {
		round2UnicastOutputs[i], err = participants[i].Round2(round2UnicastInputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run DKG round 2")
		}
	}
	return round2UnicastOutputs, nil
}

func DoDkgRound3(mySigningKeyShares []*tsignatures.SigningKeyShare, participants []*dkg.Participant, round3UnicastInputs []types.RoundMessages[*dkg.Round2P2P]) (shards []*dkls24.Shard, err error) {
	shards = make([]*dkls24.Shard, len(participants))
	for i := range participants {
		shards[i], err = participants[i].Round3(mySigningKeyShares[i], round3UnicastInputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run DKG round 3")
		}
	}
	return shards, nil
}

func RunDKG(curve curves.Curve, protocol types.ThresholdProtocol, identities []types.IdentityKey) (participants []*dkg.Participant, shards []*dkls24.Shard, err error) {
	// Run JF-DKG first
	sessionId := []byte("JoinFeldmanDkgTestSessionId")
	signingKeyShares, partialPublicKeys, err := jf_testutils.RunDKG(sessionId, protocol, identities)
	if err != nil {
		return nil, nil, err
	}

	// Run DKLs24 specifics
	participants, err = MakeDkgParticipants(curve, protocol, identities, signingKeyShares, partialPublicKeys, nil, nil)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not make DKG participants")
	}

	r1OutsU, err := DoDkgRound1(participants)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run DKG round 1")
	}

	r2InsU := ttu.MapUnicastO2I(participants, r1OutsU)
	r2OutsU, err := DoDkgRound2(participants, r2InsU)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run DKG round 2")
	}

	r3InsU := ttu.MapUnicastO2I(participants, r2OutsU)
	shards, err = DoDkgRound3(signingKeyShares, participants, r3InsU)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run DKG round 3")
	}
	return participants, shards, nil
}
