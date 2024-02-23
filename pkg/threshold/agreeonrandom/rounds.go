package agreeonrandom

import (
	"sort"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs"
)

type Round1Broadcast struct {
	Commitment commitments.Commitment

	_ ds.Incomparable
}
type Round2Broadcast struct {
	Ri      curves.Scalar
	Witness commitments.Witness

	_ ds.Incomparable
}

func (p *Participant) Round1() (*Round1Broadcast, error) {
	if p.round != 1 {
		return nil, errs.NewRound("round mismatch %d != 1", p.round)
	}
	// step 1.1: sample a random scalar r_i
	r_i, err := p.Protocol.Curve().ScalarField().Random(p.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate random scalar")
	}
	// step 1.2: commit your sample
	commitment, witness, err := commitments.CommitWithoutSession(p.prng, r_i.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not commit to the seed for participant %x", p.IdentityKey().PublicKey().ToAffineCompressed())
	}
	p.round++
	p.state.r_i = r_i
	p.state.witness = witness
	// step 1.3: broadcast your commitment
	return &Round1Broadcast{
		Commitment: commitment,
	}, nil
}

func (p *Participant) Round2(round1output types.RoundMessages[*Round1Broadcast]) (*Round2Broadcast, error) {
	if p.round != 2 {
		return nil, errs.NewRound("round mismatch %d != 2", p.round)
	}

	for party := range p.Protocol.Participants().Iter() {
		if party.Equal(p.myAuthKey) {
			continue
		}
		sender := party
		round1Msg, exists := round1output.Get(party)
		if !exists {
			return nil, errs.NewArgument("no response")
		}
		if len(round1Msg.Commitment) == 0 {
			return nil, errs.NewArgument("commitment is empty")
		}
		p.state.receivedCommitments.Put(sender, round1Msg.Commitment)
	}

	p.round++
	// step 2.1: broadcast your witness and your sample r_i
	return &Round2Broadcast{
		Witness: p.state.witness,
		Ri:      p.state.r_i,
	}, nil
}

func (p *Participant) Round3(round2output types.RoundMessages[*Round2Broadcast]) ([]byte, error) {
	if p.round != 3 {
		return nil, errs.NewRound("round mismatch %d != 3", p.round)
	}

	for party := range p.Protocol.Participants().Iter() {
		if party.Equal(p.myAuthKey) {
			continue
		}

		message, exists := round2output.Get(party)
		if !exists {
			return nil, errs.NewArgument("no response")
		}
		receivedCommitment, exists := p.state.receivedCommitments.Get(party)
		if !exists {
			return nil, errs.NewIdentifiableAbort(party.PublicKey().ToAffineCompressed(), "could not find commitment for participant %x", party.PublicKey())
		}
		// step 3.2: open and check the commitments
		if err := commitments.OpenWithoutSession(receivedCommitment, message.Witness, message.Ri.Bytes()); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, party.PublicKey().ToAffineCompressed(), "commitment from participant with sharing id can't be opened")
		}
	}

	round2output.Put(p.IdentityKey(), &Round2Broadcast{
		Ri: p.state.r_i,
	})
	sortRandomnessContributions, err := p.sortRandomnessContributions(round2output)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't derive r vector")
	}
	// step 3.3: hash to derive the random value
	p.state.transcript.AppendMessages("sid contribution", sortRandomnessContributions...)
	randomValue, err := p.state.transcript.ExtractBytes("session id", przs.LambdaBytes)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't derive random value")
	}
	p.round++
	return randomValue, nil
}

func (p *Participant) sortRandomnessContributions(allIdentityKeysToRi types.RoundMessages[*Round2Broadcast]) ([][]byte, error) {
	sortedIdentityIndices := p.IdentitySpace.Keys()
	sort.Slice(sortedIdentityIndices, func(i, j int) bool { return sortedIdentityIndices[i] < sortedIdentityIndices[j] })
	sortedRVector := make([][]byte, allIdentityKeysToRi.Size())
	for i, identityIndex := range sortedIdentityIndices {
		identityKey, exists := p.IdentitySpace.Get(identityIndex)
		if !exists {
			return nil, errs.NewMissing("couldn't find identity key %d", identityIndex)
		}
		message, exists := allIdentityKeysToRi.Get(identityKey)
		if !exists {
			return nil, errs.NewMissing("message couldn't be found")
		}
		sortedRVector[i] = message.Ri.Bytes()
	}

	return sortedRVector, nil
}
