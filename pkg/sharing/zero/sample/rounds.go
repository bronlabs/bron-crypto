package sample

import (
	"fmt"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/zero"
)

type Round1Broadcast struct {
	Ri curves.Scalar
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

func (p *Participant) Round2(round1output map[integration.IdentityKey]*Round1Broadcast) (zero.Sample, error) {
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

	sample := p.Curve.Scalar.Zero()
	for _, participant := range p.PresentParticipants {
		sharingId := p.IdentityKeyToSharingId[participant]
		if sharingId == p.MySharingId {
			continue
		}
		sharedSeed, exists := p.Seeds[participant]
		if !exists {
			return nil, errs.NewMissing("could not find shared seeds for sharing id %d", sharingId)
		}
		// TODO: make hash to curve and scalars variadic
		toBeHashed := append(sid, sharedSeed[:]...)
		sampled := p.Curve.Scalar.Hash(toBeHashed)
		if p.MySharingId < sharingId {
			sample = sample.Add(sampled)
		} else {
			sample = sample.Add(sampled.Neg())
		}
	}
	if sample.IsZero() {
		return nil, errs.NewFailed("could not sample a zero share")
	}
	p.round++
	return sample, nil
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
