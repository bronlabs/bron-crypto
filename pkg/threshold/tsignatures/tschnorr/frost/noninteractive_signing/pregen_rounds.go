package noninteractive_signing

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type Round1Broadcast struct {
	Tau         int
	Commitments []*AttestedCommitmentToNoncePair

	_ ds.Incomparable
}

func (p *PreGenParticipant) Round1() (*Round1Broadcast, error) {
	if p.round != 1 {
		return nil, errs.NewRound("rounds mismatch %d != 1", p.round)
	}
	p.state = &preGenState{
		ds:          make([]curves.Scalar, p.Tau),
		es:          make([]curves.Scalar, p.Tau),
		Commitments: make([]*AttestedCommitmentToNoncePair, p.Tau),
	}
	for j := 0; j < p.Tau; j++ {
		dj, err := p.Protocol.Curve().ScalarField().Random(p.prng)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "could not generate random dj")
		}
		ej, err := p.Protocol.Curve().ScalarField().Random(p.prng)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "could not generate random ej")
		}
		Dj := p.Protocol.Curve().ScalarBaseMult(dj)
		Ej := p.Protocol.Curve().ScalarBaseMult(ej)
		message := Dj.ToAffineCompressed()
		message = append(message, Ej.ToAffineCompressed()...)
		attestation := p.MyAuthKey.Sign(message)

		p.state.ds[j] = dj
		p.state.es[j] = ej
		p.state.Commitments[j] = &AttestedCommitmentToNoncePair{
			D:           Dj,
			E:           Ej,
			Attestation: attestation,
		}
	}
	p.round++
	return &Round1Broadcast{
		Tau:         p.Tau,
		Commitments: p.state.Commitments,
	}, nil
}

func (p *PreGenParticipant) Round2(round1output types.RoundMessages[*Round1Broadcast]) (PreSignatureBatch, []*PrivateNoncePair, error) {
	if p.round != 2 {
		return nil, nil, errs.NewRound("rounds mismatch %d != 1", p.round)
	}
	if _, exists := round1output.Get(p.IdentityKey()); exists {
		return nil, nil, errs.NewFailed("message found whose sender is me")
	}
	round1output.Put(p.IdentityKey(), &Round1Broadcast{
		Tau:         p.Tau,
		Commitments: p.state.Commitments,
	})
	if round1output.Size() != int(p.Protocol.TotalParties()) {
		return nil, nil, errs.NewCount("the number of received messages is not equal to total parties")
	}

	batch := make(PreSignatureBatch, p.Tau)
	privateNoncePairs := make([]*PrivateNoncePair, p.Tau)

	for i := 0; i < p.Tau; i++ {
		preSignature := make(PreSignature, p.Protocol.Participants().Size())
		j := -1
		for participant := range p.Protocol.Participants().Iter() {
			j++
			senderSharingId := j + 1
			message, exists := round1output.Get(participant)
			if !exists {
				return nil, nil, errs.NewMissing("did not receive any message from sharing id %d", senderSharingId)
			}
			participantAttestedCommitmentAtThisIndex := message.Commitments[i]
			participantAttestedCommitmentAtThisIndex.Attestor = participant
			if err := participantAttestedCommitmentAtThisIndex.Validate(p.Protocol); err != nil {
				return nil, nil, errs.WrapValidation(err, "invalid attestation for presignature index %d by party sharing id %d", i, senderSharingId)
			}
			preSignature[j] = message.Commitments[i]
		}
		if err := preSignature.Validate(p.Protocol); err != nil {
			return nil, nil, errs.WrapValidation(err, "invalid presignature")
		}
		batch[i] = preSignature
		privateNoncePairs[i] = &PrivateNoncePair{
			SmallD: p.state.ds[i],
			SmallE: p.state.es[i],
		}
	}
	if err := batch.Validate(p.Protocol); err != nil {
		return nil, nil, errs.WrapValidation(err, "invalid pre signature batch")
	}
	p.round++
	return batch, privateNoncePairs, nil
}
