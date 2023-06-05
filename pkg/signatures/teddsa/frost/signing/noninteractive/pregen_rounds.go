package noninteractive

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/error_types"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/pkg/errors"
)

type Round1Broadcast struct {
	Tau         int
	Commitments []*AttestedCommitmentToNoncePair
}

func (p *PreGenParticipant) Round1() (*Round1Broadcast, error) {
	if p.round != 1 {
		return nil, errors.Errorf("%s rounds mismatch %d != 1", error_types.EInvalidRound, p.round)
	}
	p.state = &preGenState{
		ds:          make([]curves.Scalar, p.Tau),
		es:          make([]curves.Scalar, p.Tau),
		Commitments: make([]*AttestedCommitmentToNoncePair, p.Tau),
	}
	for j := 0; j < p.Tau; j++ {
		dj := p.CohortConfig.CipherSuite.Curve.Scalar.Random(p.prng)
		ej := p.CohortConfig.CipherSuite.Curve.Scalar.Random(p.prng)
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
		return nil, nil, errors.Errorf("%s rounds mismatch %d != 1", error_types.EInvalidRound, p.round)
	}
	if _, exists := round1output[p.MyIdentityKey]; exists {
		return nil, nil, errors.Errorf("%s message found whose sender is me", error_types.EAbort)
	}
	round1output[p.MyIdentityKey] = &Round1Broadcast{
		Tau:         p.Tau,
		Commitments: p.state.Commitments,
	}
	if len(round1output) != p.CohortConfig.TotalParties {
		return nil, nil, errors.Errorf("%s the number of received messages is not equal to total parties", error_types.EAbort)
	}

	batch := make(PreSignatureBatch, p.Tau)
	privateNoncePairs := make([]*PrivateNoncePair, p.Tau)

	for i := 0; i < p.Tau; i++ {
		preSignature := make(PreSignature, len(p.CohortConfig.Participants))
		for j, participant := range p.CohortConfig.Participants {
			senderShamirId := j + 1
			message, exists := round1output[participant]
			if !exists {
				return nil, nil, errors.Errorf("%s did not receive any message from shamir id %d", error_types.EAbort, senderShamirId)
			}
			participantAttestedCommitmentAtThisIndex := message.Commitments[i]
			participantAttestedCommitmentAtThisIndex.Attestor = participant
			if err := participantAttestedCommitmentAtThisIndex.Validate(p.CohortConfig); err != nil {
				return nil, nil, errors.Wrapf(err, "invalid attestation for presignature index %d by party shamir id %d", i, senderShamirId)
			}
			preSignature[j] = message.Commitments[i]
		}
		if err := preSignature.Validate(p.CohortConfig); err != nil {
			return nil, nil, errors.Wrapf(err, "%s invalid presignature", error_types.EVerificationFailed)
		}
		batch[i] = &preSignature
		privateNoncePairs[i] = &PrivateNoncePair{
			SmallD: p.state.ds[i],
			SmallE: p.state.es[i],
		}
	}
	if err := batch.Validate(p.CohortConfig); err != nil {
		return nil, nil, errors.Wrapf(err, "%s invalid pre signature batch", error_types.EVerificationFailed)
	}
	p.round++
	return &batch, privateNoncePairs, nil
}
