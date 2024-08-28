package noninteractive_signing

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
)

func (p *PreGenParticipant) Round1() (*Round1Broadcast, error) {
	// Validation
	if p.Round != 1 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 1, p.Round)
	}

	p.state = &preGenState{
		ds:          make([]curves.Scalar, p.Tau),
		es:          make([]curves.Scalar, p.Tau),
		Commitments: make([]*AttestedCommitmentToNoncePair, p.Tau),
	}
	for j := 0; j < p.Tau; j++ {
		dj, err := p.Protocol.Curve().ScalarField().Random(p.Prng)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "could not generate random dj")
		}
		ej, err := p.Protocol.Curve().ScalarField().Random(p.Prng)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "could not generate random ej")
		}
		Dj := p.Protocol.Curve().ScalarBaseMult(dj)
		Ej := p.Protocol.Curve().ScalarBaseMult(ej)
		message := Dj.ToAffineCompressed()
		message = append(message, Ej.ToAffineCompressed()...)
		attestation := p.myAuthKey.Sign(message)

		p.state.ds[j] = dj
		p.state.es[j] = ej
		p.state.Commitments[j] = &AttestedCommitmentToNoncePair{
			D:           Dj,
			E:           Ej,
			Attestation: attestation,
		}
	}

	p.Round++
	return &Round1Broadcast{
		Tau:         p.Tau,
		Commitments: p.state.Commitments,
	}, nil
}

func (p *PreGenParticipant) Round2(round1output network.RoundMessages[types.ThresholdProtocol, *Round1Broadcast]) (PreSignatureBatch, []*PrivateNoncePair, error) {
	// Validation
	if p.Round != 2 {
		return nil, nil, errs.NewRound("Running round %d but participant expected round %d", 2, p.Round)
	}
	if err := network.ValidateMessages(p.Protocol, p.Protocol.Participants(), p.IdentityKey(), round1output); err != nil {
		return nil, nil, errs.WrapFailed(err, "invalid round %d input", p.Round)
	}

	round1output.Put(p.IdentityKey(), &Round1Broadcast{
		Tau:         p.Tau,
		Commitments: p.state.Commitments,
	})
	if round1output.Size() != int(p.Protocol.TotalParties()) {
		return nil, nil, errs.NewSize("the number of received messages is not equal to total parties")
	}

	batch := make(PreSignatureBatch, p.Tau)
	privateNoncePairs := make([]*PrivateNoncePair, p.Tau)

	for i := 0; i < p.Tau; i++ {
		preSignature := make(PreSignature, p.Protocol.Participants().Size())
		j := -1
		for participant := range p.Protocol.Participants().Iter() {
			j++
			senderSharingId := j + 1
			message, _ := round1output.Get(participant)
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

	p.Round++
	return batch, privateNoncePairs, nil
}
