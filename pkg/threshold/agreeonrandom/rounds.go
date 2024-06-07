package agreeonrandom

import (
	"bytes"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	hashcommitments "github.com/copperexchange/krypton-primitives/pkg/commitments/hash"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/rprzs"
)

func (p *Participant) Round1() (*Round1Broadcast, error) {
	// Validation
	if p.Round != 1 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 1, p.Round)
	}

	// step 1.1: sample a random scalar r_i
	r_i, err := p.Protocol.Curve().ScalarField().Random(p.Prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate random scalar")
	}

	// step 1.2: commit your sample
	committer, err := hashcommitments.NewCommitter(nil, p.Prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot instantiate committer")
	}
	commitment, opening, err := committer.Commit(r_i.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not commit to the seed for participant %x", p.IdentityKey().String())
	}
	p.state.r_i = r_i
	p.state.opening = opening

	// step 1.3: broadcast your commitment
	p.Round++
	return &Round1Broadcast{
		Commitment: commitment,
	}, nil
}

func (p *Participant) Round2(round1output network.RoundMessages[types.Protocol, *Round1Broadcast]) (*Round2Broadcast, error) {
	// Validation
	if p.Round != 2 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 2, p.Round)
	}
	if err := network.ValidateMessages(p.Protocol, p.Protocol.Participants(), p.IdentityKey(), round1output); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 1 messages")
	}

	// step 2.0: store all commitments
	for iterator := p.Protocol.Participants().Iterator(); iterator.HasNext(); {
		sender := iterator.Next()
		if sender.Equal(p.myAuthKey) {
			continue
		}
		round1Msg, _ := round1output.Get(sender)
		p.state.receivedCommitments.Put(sender, round1Msg.Commitment)
	}

	// step 2.1: broadcast your witness and your sample r_i
	p.Round++
	return &Round2Broadcast{
		Opening: p.state.opening,
		Ri:      p.state.r_i,
	}, nil
}

func (p *Participant) Round3(round2output network.RoundMessages[types.Protocol, *Round2Broadcast]) (randomValue []byte, err error) {
	// Validation
	if p.Round != 3 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 3, p.Round)
	}
	if err := network.ValidateMessages(p.Protocol, p.Protocol.Participants(), p.IdentityKey(), round2output); err != nil {
		return nil, errs.WrapValidation(err, "invalid ound 1 messages")
	}

	// step 3.1: for each participant...
	for iterator := p.Protocol.Participants().Iterator(); iterator.HasNext(); {
		party := iterator.Next()
		if party.Equal(p.myAuthKey) {
			continue
		}
		message, _ := round2output.Get(party)
		receivedCommitment, _ := p.state.receivedCommitments.Get(party)
		// step 3.2: open and check the commitments
		verifier := hashcommitments.NewVerifier(nil)
		if !bytes.Equal(message.Opening.GetMessage(), message.Ri.Bytes()) {
			return nil, errs.NewVerification("opening is not tied to the expected message")
		}
		if err := verifier.Verify(receivedCommitment, message.Opening); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, party.String(), "commitment from participant with sharing id can't be opened")
		}
	}
	// Sort all the contributions to hash them in a deterministic order
	round2output.Put(p.IdentityKey(), &Round2Broadcast{
		Ri: p.state.r_i,
	})
	sortedMessages, err := network.SortMessages(p.Protocol, round2output)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't sort r2 broadcast messages")
	}
	sortRandomnessContributions := make([][]byte, len(sortedMessages))
	for i, message := range sortedMessages {
		sortRandomnessContributions[i] = message.Ri.Bytes()
	}

	// step 3.3: hash to derive the random value
	p.Transcript.AppendMessages("sid contribution", sortRandomnessContributions...)
	if randomValue, err = p.Transcript.ExtractBytes("session id", rprzs.LambdaBytes); err != nil {
		return nil, errs.WrapFailed(err, "couldn't derive random value")
	}

	p.Round++
	return randomValue, nil
}
