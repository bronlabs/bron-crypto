package agreeonrandom

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs"
)

func (p *Participant) Round1() (*Round1Broadcast, error) {
	// Validation
	if err := p.InRound(1); err != nil {
		return nil, errs.WrapValidation(err, "Participant in invalid round")
	}

	// step 1.1: sample a random scalar r_i
	r_i, err := p.Protocol().Curve().ScalarField().Random(p.Prng())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate random scalar")
	}

	// step 1.2: commit your sample
	commitment, witness, err := commitments.CommitWithoutSession(p.Prng(), r_i.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not commit to the seed for participant %x", p.IdentityKey().String())
	}
	p.state.r_i = r_i
	p.state.witness = witness

	// step 1.3: broadcast your commitment
	p.NextRound()
	return &Round1Broadcast{
		Commitment: commitment,
	}, nil
}

func (p *Participant) Round2(round1output network.RoundMessages[*Round1Broadcast]) (*Round2Broadcast, error) {
	// Validation
	if err := p.InRound(2); err != nil {
		return nil, errs.WrapValidation(err, "Participant in invalid round")
	}
	if err := network.ValidateMessages(p.Protocol().Participants(), p.IdentityKey(), round1output); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 1 messages")
	}

	// step 2.0: store all commitments
	for party := range p.Protocol().Participants().Iter() {
		if party.Equal(p.myAuthKey) {
			continue
		}
		sender := party
		round1Msg, _ := round1output.Get(party)
		p.state.receivedCommitments.Put(sender, round1Msg.Commitment)
	}

	// step 2.1: broadcast your witness and your sample r_i
	p.NextRound()
	return &Round2Broadcast{
		Witness: p.state.witness,
		Ri:      p.state.r_i,
	}, nil
}

func (p *Participant) Round3(round2output network.RoundMessages[*Round2Broadcast]) (randomValue []byte, err error) {
	// Validation
	if err := p.InRound(3); err != nil {
		return nil, errs.WrapValidation(err, "Participant in invalid round")
	}
	if err := network.ValidateMessages(p.Protocol().Participants(), p.IdentityKey(), round2output); err != nil {
		return nil, errs.WrapValidation(err, "invalid ound 1 messages")
	}

	// step 3.1: for each participant...
	for party := range p.Protocol().Participants().Iter() {
		if party.Equal(p.myAuthKey) {
			continue
		}
		message, _ := round2output.Get(party)
		receivedCommitment, _ := p.state.receivedCommitments.Get(party)
		// step 3.2: open and check the commitments
		if err := commitments.OpenWithoutSession(receivedCommitment, message.Witness, message.Ri.Bytes()); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, party.String(), "commitment from participant with sharing id can't be opened")
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
	p.Transcript().AppendMessages("sid contribution", sortRandomnessContributions...)
	if randomValue, err = p.Transcript().ExtractBytes("session id", przs.LambdaBytes); err != nil {
		return nil, errs.WrapFailed(err, "couldn't derive random value")
	}

	p.LastRound()
	return randomValue, nil
}
