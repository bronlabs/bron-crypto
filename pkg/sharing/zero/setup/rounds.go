package setup

import (
	"fmt"

	"github.com/copperexchange/crypto-primitives-go/pkg/commitments"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/hashing"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/zero"
	"golang.org/x/crypto/sha3"
)

var h = sha3.New256

type Round1Broadcast struct {
	Ri curves.Scalar
}

type Round2P2P struct {
	Commitment commitments.Commitment
}

type Round3P2P struct {
	Message []byte
	Witness commitments.Witness
}

func (p *Participant) Round1() (*Round1Broadcast, error) {
	if p.round != 1 {
		return nil, errs.NewInvalidRound("round mismatch %d != 1", p.round)
	}
	p.state.r_i = p.Curve.Scalar.Random(p.prng)
	p.round++
	return &Round1Broadcast{
		Ri: p.state.r_i,
	}, nil

}

func (p *Participant) Round2(round1output map[integration.IdentityKey]*Round1Broadcast) (map[integration.IdentityKey]*Round2P2P, error) {
	if p.round != 2 {
		return nil, errs.NewInvalidRound("round mismatch %d != 2", p.round)
	}
	round1output[p.MyIdentityKey] = &Round1Broadcast{
		Ri: p.state.r_i,
	}
	sortedSidContributions, err := sortSidContributions(round1output)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't derive r vector")
	}
	for i, sidFromI := range sortedSidContributions {
		p.state.transcript.AppendMessage([]byte(fmt.Sprintf("sid contribution from %d", i)), sidFromI)
	}
	sid := p.state.transcript.ExtractBytes([]byte("session id"), zero.LambdaBytes)

	output := map[integration.IdentityKey]*Round2P2P{}
	for i, participant := range p.Participants {
		if participant.PublicKey().Equal(p.MyIdentityKey.PublicKey()) {
			continue
		}
		randomBytes := zero.Seed{}
		if _, err := p.prng.Read(randomBytes[:]); err != nil {
			return nil, errs.NewFailed("could not produce random bytes for party number %d", i)
		}
		seedForThisParticipant, err := hashing.Hash(h, sid, randomBytes[:])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not produce seed for participant number %d", i)
		}
		commitment, witness, err := commitments.Commit(h, seedForThisParticipant)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not commit to the seed for participant %d", i)
		}
		p.state.sentSeeds[participant] = &committedSeedContribution{
			seed:       seedForThisParticipant,
			commitment: commitment,
			witness:    witness,
		}
		output[participant] = &Round2P2P{
			Commitment: commitment,
		}
	}
	p.round++
	return output, nil
}

func (p *Participant) Round3(round2output map[integration.IdentityKey]*Round2P2P) (zero.Seed, error) {
	if p.round != 3 {
		return zero.Seed{}, errs.NewInvalidRound("round mismatch %d != 3", p.round)
	}
	for _, participant := range p.Participants {
		sharingId := p.IdentityKeyToSharingId[participant]
		if participant.PublicKey().Equal(p.MyIdentityKey.PublicKey()) {
			continue
		}
		message, exists := round2output[participant]
		if !exists {
			return zero.Seed{}, errs.NewMissing("no message was received from participant with sharing id %d", sharingId)
		}
	}
}

func sortSidContributions(allIdentityKeysToRi map[integration.IdentityKey]*Round1Broadcast) ([][]byte, error) {
	identityKeys := make([]integration.IdentityKey, len(allIdentityKeysToRi))
	i := 0
	for identityKey := range allIdentityKeysToRi {
		identityKeys[i] = identityKey
		i++
	}
	identityKeys = integration.SortIdentityKeys(identityKeys)
	sortedRVector := make([][]byte, len(allIdentityKeysToRi))
	for i, identityKey := range identityKeys {
		message, exists := allIdentityKeysToRi[identityKey]
		if !exists {
			return nil, errs.NewMissing("message couldn't be found")
		}
		sortedRVector[i] = message.Ri.Bytes()
	}

	return sortedRVector, nil

}
