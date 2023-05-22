package noninteractive

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/pkg/errors"
)

type Round1Broadcast struct {
	Tau         int
	Commitments []*AttestedCommitmentToNoncePair
}

func (p *PreGenParticipant) Round1() (*Round1Broadcast, error) {
	if p.round != 1 {
		return nil, errors.New("rounds mismatch")
	}
	p.state = &preGenState{
		ds:          make([]curves.Scalar, p.Tau),
		es:          make([]curves.Scalar, p.Tau),
		Commitments: make([]*AttestedCommitmentToNoncePair, p.Tau),
	}
	for j := 0; j < p.Tau; j++ {
		dj := p.CohortConfig.CipherSuite.Curve.Scalar.Random(p.reader)
		ej := p.CohortConfig.CipherSuite.Curve.Scalar.Random(p.reader)
		Dj := p.CohortConfig.CipherSuite.Curve.ScalarBaseMult(dj)
		Ej := p.CohortConfig.CipherSuite.Curve.ScalarBaseMult(ej)
		message := Dj.ToAffineCompressed()
		message = append(message, Ej.ToAffineCompressed()...)
		attestation := p.MyIdentityKey.Sign(message)

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

func (p *PreGenParticipant) Round2(round1output map[integration.IdentityKey]*Round1Broadcast) (*PreSignatureBatch, []*PrivateNoncePair, error) {
	if p.round != 2 {
		return nil, nil, errors.New("rounds mismatch")
	}
	if _, exists := round1output[p.MyIdentityKey]; exists {
		return nil, nil, errors.New("message found whose sender is me")
	}
	round1output[p.MyIdentityKey] = &Round1Broadcast{
		Tau:         p.Tau,
		Commitments: p.state.Commitments,
	}
	if len(round1output) != p.CohortConfig.TotalParties {
		return nil, nil, errors.New("the number of received messages is not equal to total parties")
	}

	batch := make(PreSignatureBatch, p.Tau)
	privateNoncePairs := make([]*PrivateNoncePair, p.Tau)

	for i := 0; i < p.Tau; i++ {
		preSignature := make(PreSignature, len(p.CohortConfig.Participants))
		for j, participant := range p.CohortConfig.Participants {
			senderShamirId := j + 1
			message, exists := round1output[participant]
			if !exists {
				return nil, nil, errors.Errorf("did not receive any message from shamir id %d", senderShamirId)
			}
			participantAttestedCommitmentAtThisIndex := message.Commitments[i]
			participantAttestedCommitmentAtThisIndex.Attestor = participant
			if err := participantAttestedCommitmentAtThisIndex.Validate(p.CohortConfig); err != nil {
				return nil, nil, errors.Wrapf(err, "invalid attestation for presignature index %d by party shamir id %d", i, senderShamirId)
			}
			preSignature[j] = message.Commitments[i]
		}
		if err := preSignature.Validate(p.CohortConfig); err != nil {
			return nil, nil, errors.Wrap(err, "invalid presignature")
		}
		batch[i] = &preSignature
		privateNoncePairs[i] = &PrivateNoncePair{
			SmallD: p.state.ds[i],
			SmallE: p.state.es[i],
		}
	}
	if err := batch.Validate(p.CohortConfig); err != nil {
		return nil, nil, errors.Wrap(err, "invalid pre signature batch")
	}
	p.round++
	return &batch, privateNoncePairs, nil
}
