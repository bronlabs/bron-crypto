package testutils

import (
	crand "crypto/rand"
	"io"
	"sync"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
	agreeonrandomTestutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	jf_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/jf/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23/keygen/dkg"
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

func DoDkgRound1(participants []*dkg.Participant) (round1UnicastOutputs []network.RoundMessages[types.ThresholdProtocol, *dkg.Round1P2P], err error) {
	round1UnicastOutputs = make([]network.RoundMessages[types.ThresholdProtocol, *dkg.Round1P2P], len(participants))
	for i, participant := range participants {
		round1UnicastOutputs[i], err = participant.Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run DKG round 1")
		}
	}

	return round1UnicastOutputs, nil
}

func DoDkgRound2(participants []*dkg.Participant, round2UnicastInputs []network.RoundMessages[types.ThresholdProtocol, *dkg.Round1P2P]) (round2UnicastOutputs []network.RoundMessages[types.ThresholdProtocol, *dkg.Round2P2P], err error) {
	round2UnicastOutputs = make([]network.RoundMessages[types.ThresholdProtocol, *dkg.Round2P2P], len(participants))
	for i := range participants {
		round2UnicastOutputs[i], err = participants[i].Round2(round2UnicastInputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run DKG round 2")
		}
	}
	return round2UnicastOutputs, nil
}

func DoDkgRound3(mySigningKeyShares []*tsignatures.SigningKeyShare, participants []*dkg.Participant, round3UnicastInputs []network.RoundMessages[types.ThresholdProtocol, *dkg.Round2P2P]) (shards []*dkls23.Shard, err error) {
	shards = make([]*dkls23.Shard, len(participants))
	for i := range participants {
		shards[i], err = participants[i].Round3(mySigningKeyShares[i], round3UnicastInputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not run DKG round 3")
		}
	}
	return shards, nil
}

func DoDkgRound1WithParallelParties(participants []*dkg.Participant) (round1UnicastOutputs []network.RoundMessages[types.ThresholdProtocol, *dkg.Round1P2P], err error) {
	r1uOut := make(chan []network.RoundMessages[types.ThresholdProtocol, *dkg.Round1P2P])
	go func() {
		var wg sync.WaitGroup
		round1UnicastOutputs := make([]network.RoundMessages[types.ThresholdProtocol, *dkg.Round1P2P], len(participants))
		errch := make(chan error, len(participants))

		// Round 1
		for i, participant := range participants {
			wg.Add(1)
			go func(i int, participant *dkg.Participant) {
				defer wg.Done()
				var err error
				round1UnicastOutputs[i], err = participant.Round1()
				if err != nil {
					errch <- errs.WrapFailed(err, "could not execute round 1")
				}
			}(i, participant)
		}
		wg.Wait()
		close(errch)
		r1uOut <- round1UnicastOutputs
		close(r1uOut)
	}()
	return <-r1uOut, nil
}

func DoDkgRound2WithParallelParties(participants []*dkg.Participant, round2UnicastInputs []network.RoundMessages[types.ThresholdProtocol, *dkg.Round1P2P]) (round2UnicastOutputs []network.RoundMessages[types.ThresholdProtocol, *dkg.Round2P2P], err error) {
	r2uOut := make(chan []network.RoundMessages[types.ThresholdProtocol, *dkg.Round2P2P])
	go func() {
		var wg sync.WaitGroup
		round2UnicastOutputs := make([]network.RoundMessages[types.ThresholdProtocol, *dkg.Round2P2P], len(participants))
		errch := make(chan error, len(participants))

		// Round 2
		for i, participant := range participants {
			wg.Add(1)
			go func(i int, participant *dkg.Participant) {
				defer wg.Done()
				var err error
				round2UnicastOutputs[i], err = participant.Round2(round2UnicastInputs[i])
				if err != nil {
					errch <- errs.WrapFailed(err, "could not execute round 2")
				}
			}(i, participant)
		}
		wg.Wait()
		close(errch)
		r2uOut <- round2UnicastOutputs
		close(r2uOut)
	}()
	return <-r2uOut, nil
}

func DoDkgRound3WithParallelParties(mySigningKeyShares []*tsignatures.SigningKeyShare, participants []*dkg.Participant, round3UnicastInputs []network.RoundMessages[types.ThresholdProtocol, *dkg.Round2P2P]) (shards []*dkls23.Shard, err error) {
	r3Out := make(chan []*dkls23.Shard)
	go func() {
		var wg sync.WaitGroup
		shards := make([]*dkls23.Shard, len(participants))
		errch := make(chan error, len(participants))

		// Round 3
		for i, participant := range participants {
			wg.Add(1)
			go func(i int, participant *dkg.Participant) {
				defer wg.Done()
				var err error
				shards[i], err = participant.Round3(mySigningKeyShares[i], round3UnicastInputs[i])
				if err != nil {
					errch <- errs.WrapFailed(err, "could not execute round 3")
				}
			}(i, participant)
		}
		wg.Wait()
		close(errch)
		r3Out <- shards
		close(r3Out)
	}()
	return <-r3Out, nil
}

func RunDKG(curve curves.Curve, protocol types.ThresholdProtocol, identities []types.IdentityKey) (participants []*dkg.Participant, shards []*dkls23.Shard, err error) {
	// Run JF-DKG first
	sessionId := []byte("JoinFeldmanDkgTestSessionId")
	signingKeyShares, partialPublicKeys, err := jf_testutils.RunDKG(sessionId, protocol, identities)
	if err != nil {
		return nil, nil, err
	}

	// Run DKLs23 specifics
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

func RunDKGWithParallelParties(curve curves.Curve, protocol types.ThresholdProtocol, identities []types.IdentityKey) (participants []*dkg.Participant, shards []*dkls23.Shard, err error) {
	// Run JF-DKG first
	sessionId := []byte("JoinFeldmanDkgTestSessionId")
	signingKeyShares, partialPublicKeys, err := jf_testutils.RunDKGWithParallelParties(sessionId, protocol, identities)
	if err != nil {
		return nil, nil, err
	}

	// Run DKLs23 specifics
	participants, err = MakeDkgParticipants(curve, protocol, identities, signingKeyShares, partialPublicKeys, nil, nil)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not make DKG participants")
	}

	r1OutsU, err := DoDkgRound1WithParallelParties(participants)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run DKG round 1")
	}

	r2InsU := ttu.MapUnicastO2I(participants, r1OutsU)
	r2OutsU, err := DoDkgRound2WithParallelParties(participants, r2InsU)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run DKG round 2")
	}

	r3InsU := ttu.MapUnicastO2I(participants, r2OutsU)
	shards, err = DoDkgRound3WithParallelParties(signingKeyShares, participants, r3InsU)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run DKG round 3")
	}
	return participants, shards, nil
}
