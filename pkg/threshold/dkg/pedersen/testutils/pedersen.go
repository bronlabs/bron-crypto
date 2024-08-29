package testutils

import (
	crand "crypto/rand"
	"io"
	"sync"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/pedersen"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
)

func MakeParticipants(uniqueSessionId []byte, config types.ThresholdProtocol, identities []types.IdentityKey, prngs []io.Reader) (participants []*pedersen.Participant, err error) {
	if len(identities) != int(config.TotalParties()) {
		return nil, errs.NewLength("invalid number of identities %d != %d", len(identities), config.TotalParties())
	}

	participants = make([]*pedersen.Participant, config.TotalParties())
	for i, identity := range identities {
		var prng io.Reader
		if len(prngs) != 0 && prngs[i] != nil {
			prng = prngs[i]
		} else {
			prng = crand.Reader
		}

		if !config.Participants().Contains(identity) {
			return nil, errs.NewMissing("given test identity not a participant (problem in tests?)")
		}

		participants[i], err = pedersen.NewParticipant(uniqueSessionId, identity.(types.AuthKey), config, randomisedFischlin.Name, nil, prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct participant")
		}
	}

	return participants, nil
}

func DoDkgRound1(participants []*pedersen.Participant, a_i0s []curves.Scalar) (round1BroadcastOutputs []*pedersen.Round1Broadcast, round1UnicastOutputs []network.RoundMessages[types.ThresholdProtocol, *pedersen.Round1P2P], err error) {
	round1BroadcastOutputs = make([]*pedersen.Round1Broadcast, len(participants))
	round1UnicastOutputs = make([]network.RoundMessages[types.ThresholdProtocol, *pedersen.Round1P2P], len(participants))
	for i, participant := range participants {
		var a_i0 curves.Scalar
		if a_i0s == nil {
			a_i0 = nil
		} else {
			a_i0 = a_i0s[i]
		}
		round1BroadcastOutputs[i], round1UnicastOutputs[i], err = participant.Round1(a_i0)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not run Pedersen DKG round 1")
		}
	}

	return round1BroadcastOutputs, round1UnicastOutputs, nil
}

func DoDkgRound2(participants []*pedersen.Participant, round2BroadcastInputs []network.RoundMessages[types.ThresholdProtocol, *pedersen.Round1Broadcast], round2UnicastInputs []network.RoundMessages[types.ThresholdProtocol, *pedersen.Round1P2P]) (signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PartialPublicKeys, err error) {
	signingKeyShares = make([]*tsignatures.SigningKeyShare, len(participants))
	publicKeyShares = make([]*tsignatures.PartialPublicKeys, len(participants))
	for i := range participants {
		signingKeyShares[i], publicKeyShares[i], err = participants[i].Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "Participant %d could not run Pedersen DKG round 2", i)
		}
	}

	return signingKeyShares, publicKeyShares, nil
}

func DoDkgRound1WithParallelParties(participants []*pedersen.Participant, a_i0s []curves.Scalar) (round1BroadcastOutputs []*pedersen.Round1Broadcast, round1UnicastOutputs []network.RoundMessages[types.ThresholdProtocol, *pedersen.Round1P2P], err error) {
	r1bOut := make(chan []*pedersen.Round1Broadcast)
	r1uOut := make(chan []network.RoundMessages[types.ThresholdProtocol, *pedersen.Round1P2P])

	go func() {
		var wg sync.WaitGroup
		round1BroadcastOutputs := make([]*pedersen.Round1Broadcast, len(participants))
		round1UnicastOutputs := make([]network.RoundMessages[types.ThresholdProtocol, *pedersen.Round1P2P], len(participants))
		errch := make(chan error, len(participants))

		// Round 1
		for i, participant := range participants {
			wg.Add(1)
			go func(i int, participant *pedersen.Participant) {
				defer wg.Done()
				var err error
				var a_i0 curves.Scalar
				if a_i0s == nil {
					a_i0 = nil
				} else {
					a_i0 = a_i0s[i]
				}
				round1BroadcastOutputs[i], round1UnicastOutputs[i], err = participant.Round1(a_i0)
				if err != nil {
					errch <- errs.WrapFailed(err, "could not Pedersen DKG round 1")
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

func DoDkgRound2WithParallelParties(participants []*pedersen.Participant, round2BroadcastInputs []network.RoundMessages[types.ThresholdProtocol, *pedersen.Round1Broadcast], round2UnicastInputs []network.RoundMessages[types.ThresholdProtocol, *pedersen.Round1P2P]) (signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PartialPublicKeys, err error) {
	signingKeySharesCh := make(chan []*tsignatures.SigningKeyShare)
	publicKeySharesCh := make(chan []*tsignatures.PartialPublicKeys)

	go func() {
		var wg sync.WaitGroup
		signingKeyShares := make([]*tsignatures.SigningKeyShare, len(participants))
		publicKeyShares := make([]*tsignatures.PartialPublicKeys, len(participants))
		errch := make(chan error, len(participants))

		// Round 2
		for i, participant := range participants {
			wg.Add(1)
			go func(i int, participant *pedersen.Participant) {
				defer wg.Done()
				var err error
				signingKeyShares[i], publicKeyShares[i], err = participant.Round2(round2BroadcastInputs[i], round2UnicastInputs[i])
				if err != nil {
					errch <- errs.WrapFailed(err, "could not execute round 1")
				}
			}(i, participant)
		}
		wg.Wait()
		close(errch)
		signingKeySharesCh <- signingKeyShares
		publicKeySharesCh <- publicKeyShares
		close(signingKeySharesCh)
		close(publicKeySharesCh)
	}()
	return <-signingKeySharesCh, <-publicKeySharesCh, nil
}
