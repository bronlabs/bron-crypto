package testutils

import (
	crand "crypto/rand"
	"io"
	"sync"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/jf"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
)

func MakeParticipants(uniqueSessionId []byte, protocol types.ThresholdProtocol, identities []types.IdentityKey, niCompilerName compiler.Name, prngs []io.Reader) (participants []*jf.Participant, err error) {
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

func DoDkgRound1(participants []*jf.Participant) (round1BroadcastOutputs []*jf.Round1Broadcast, round1UnicastOutputs []network.RoundMessages[types.ThresholdProtocol, *jf.Round1P2P], err error) {
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

func DoDkgRound1WithParallelParties(participants []*jf.Participant) (round1BroadcastOutputs []*jf.Round1Broadcast, round1UnicastOutputs []network.RoundMessages[types.ThresholdProtocol, *jf.Round1P2P], err error) {
	r1bOut := make(chan []*jf.Round1Broadcast)
	r1uOut := make(chan []network.RoundMessages[types.ThresholdProtocol, *jf.Round1P2P])

	go func() {
		var wg sync.WaitGroup
		round1BroadcastOutputs := make([]*jf.Round1Broadcast, len(participants))
		round1UnicastOutputs := make([]network.RoundMessages[types.ThresholdProtocol, *jf.Round1P2P], len(participants))
		errch := make(chan error, len(participants))

		// Round 1
		for i, participant := range participants {
			wg.Add(1)
			go func(i int, participant *jf.Participant) {
				defer wg.Done()
				var err error
				round1BroadcastOutputs[i], round1UnicastOutputs[i], err = participant.Round1()
				if err != nil {
					errch <- errs.WrapFailed(err, "could not execute round 1")
				}
			}(i, participant)
		}
		wg.Wait()
		close(errch)
		r1bOut <- round1BroadcastOutputs
		close(r1bOut)
		r1uOut <- round1UnicastOutputs
		close(r1uOut)
	}()

	return <-r1bOut, <-r1uOut, nil
}

func DoDkgRound2(participants []*jf.Participant, round2BroadcastInputs []network.RoundMessages[types.ThresholdProtocol, *jf.Round1Broadcast], round2UnicastInputs []network.RoundMessages[types.ThresholdProtocol, *jf.Round1P2P]) (round2Outputs []*jf.Round2Broadcast, err error) {
	round2Outputs = make([]*jf.Round2Broadcast, len(participants))
	for i := range participants {
		round2Outputs[i], err = participants[i].Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "%s could not run JF round 2", participants[i].IdentityKey().String())
		}
	}
	return round2Outputs, nil
}
func DoDkgRound2WithParallelParties(participants []*jf.Participant, round2BroadcastInputs []network.RoundMessages[types.ThresholdProtocol, *jf.Round1Broadcast], round2UnicastInputs []network.RoundMessages[types.ThresholdProtocol, *jf.Round1P2P]) (round2Outputs []*jf.Round2Broadcast, err error) {
	r2bOut := make(chan []*jf.Round2Broadcast)

	go func() {
		var wg sync.WaitGroup
		round2BroadcastOutputs := make([]*jf.Round2Broadcast, len(participants))
		errch := make(chan error, len(participants))

		// Round 2
		for i, participant := range participants {
			wg.Add(1)
			go func(i int, participant *jf.Participant) {
				defer wg.Done()
				var err error
				round2BroadcastOutputs[i], err = participant.Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
				if err != nil {
					errch <- errs.WrapFailed(err, "could not execute round 1")
				}
			}(i, participant)
		}
		wg.Wait()
		close(errch)
		r2bOut <- round2BroadcastOutputs
		close(r2bOut)
	}()
	return <-r2bOut, nil
}

func DoDkgRound3(participants []*jf.Participant, round3Inputs []network.RoundMessages[types.ThresholdProtocol, *jf.Round2Broadcast]) (signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PartialPublicKeys, err error) {
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

func DoDkgRound3WithParallelParties(participants []*jf.Participant, round3Inputs []network.RoundMessages[types.ThresholdProtocol, *jf.Round2Broadcast]) (signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PartialPublicKeys, err error) {
	signingKeySharesCh := make(chan []*tsignatures.SigningKeyShare)
	publicKeySharesCh := make(chan []*tsignatures.PartialPublicKeys)
	go func() {
		var wg sync.WaitGroup
		signingKeys := make([]*tsignatures.SigningKeyShare, len(participants))
		publicKeys := make([]*tsignatures.PartialPublicKeys, len(participants))

		errch := make(chan error, len(participants))

		// Round 3
		for i, participant := range participants {
			wg.Add(1)
			go func(i int, participant *jf.Participant) {
				defer wg.Done()
				var err error
				signingKeys[i], publicKeys[i], err = participant.Round3(round3Inputs[i])
				if err != nil {
					errch <- errs.WrapFailed(err, "could not execute round 3")
				}
			}(i, participant)
		}
		wg.Wait()
		close(errch)
		signingKeySharesCh <- signingKeys
		publicKeySharesCh <- publicKeys
		close(signingKeySharesCh)
		close(publicKeySharesCh)
	}()

	return <-signingKeySharesCh, <-publicKeySharesCh, nil
}

func RunDKG(uniqueSessionId []byte, protocol types.ThresholdProtocol, identities []types.IdentityKey) (signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PartialPublicKeys, err error) {
	participants, err := MakeParticipants(uniqueSessionId, protocol, identities, randomisedFischlin.Name, nil)
	if err != nil {
		return nil, nil, err
	}

	r1OutsB, r1OutsU, err := DoDkgRound1(participants)
	if err != nil {
		return nil, nil, err
	}

	r2InsB, r2InsU := ttu.MapO2I(participants, r1OutsB, r1OutsU)
	r2OutsB, err := DoDkgRound2(participants, r2InsB, r2InsU)
	if err != nil {
		return nil, nil, err
	}

	r3InsB := ttu.MapBroadcastO2I(participants, r2OutsB)
	signingKeyShares, publicKeyShares, err = DoDkgRound3(participants, r3InsB)
	if err != nil {
		return nil, nil, err
	}
	return signingKeyShares, publicKeyShares, nil
}

func RunDKGWithParallelParties(uniqueSessionId []byte, protocol types.ThresholdProtocol, identities []types.IdentityKey) (signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PartialPublicKeys, err error) {
	participants, err := MakeParticipants(uniqueSessionId, protocol, identities, randomisedFischlin.Name, nil)
	if err != nil {
		return nil, nil, err
	}

	r1OutsB, r1OutsU, err := DoDkgRound1WithParallelParties(participants)
	if err != nil {
		return nil, nil, err
	}

	r2InsB, r2InsU := ttu.MapO2I(participants, r1OutsB, r1OutsU)
	r2OutsB, err := DoDkgRound2WithParallelParties(participants, r2InsB, r2InsU)
	if err != nil {
		return nil, nil, err
	}

	r3InsB := ttu.MapBroadcastO2I(participants, r2OutsB)
	signingKeyShares, publicKeyShares, err = DoDkgRound3WithParallelParties(participants, r3InsB)
	if err != nil {
		return nil, nil, err
	}
	return signingKeyShares, publicKeyShares, nil
}
