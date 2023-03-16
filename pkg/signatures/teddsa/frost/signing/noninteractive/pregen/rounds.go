package pregen

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/signing/noninteractive"
	"github.com/pkg/errors"
)

type Round1Broadcast struct {
	Tau              int
	DColumnsAttested []*noninteractive.AttestedCommitmentToNonce
	EColumnsAttested []*noninteractive.AttestedCommitmentToNonce
}

func (p *PreGenParticipant) Round1() (*Round1Broadcast, error) {
	if p.round != 1 {
		return nil, errors.New("rounds mismatch")
	}
	DColumns := make([]*noninteractive.AttestedCommitmentToNonce, p.Tau)
	EColumns := make([]*noninteractive.AttestedCommitmentToNonce, p.Tau)
	p.state = &preGenState{
		dColumns: make([]curves.Scalar, p.Tau),
		eColumns: make([]curves.Scalar, p.Tau),
	}
	for j := 0; j < p.Tau; j++ {
		dj := p.CohortConfig.CipherSuite.Curve.Scalar.Random(p.reader)
		ej := p.CohortConfig.CipherSuite.Curve.Scalar.Random(p.reader)
		Dj := p.CohortConfig.CipherSuite.Curve.ScalarBaseMult(dj)
		Ej := p.CohortConfig.CipherSuite.Curve.ScalarBaseMult(ej)
		DjAttestation := p.MyIdentityKey.Sign(Dj.ToAffineCompressed())
		EjAttestation := p.MyIdentityKey.Sign(Ej.ToAffineCompressed())

		p.state.dColumns[j] = dj
		p.state.eColumns[j] = ej
		DColumns[j] = &noninteractive.AttestedCommitmentToNonce{
			Commitment:  Dj,
			Attestor:    p.MyIdentityKey,
			Attestation: DjAttestation,
		}
		EColumns[j] = &noninteractive.AttestedCommitmentToNonce{
			Commitment:  Ej,
			Attestor:    p.MyIdentityKey,
			Attestation: EjAttestation,
		}
	}
	p.round++
	return &Round1Broadcast{
		DColumnsAttested: DColumns,
		EColumnsAttested: EColumns,
	}, nil
}

func (p *PreGenParticipant) Round2(round1output map[integration.IdentityKey]*Round1Broadcast) ([]*noninteractive.PreSignature, []*noninteractive.PrivateNoncePair, error) {
	if p.round != 2 {
		return nil, nil, errors.New("rounds mismatch")
	}
	if len(round1output) != p.CohortConfig.TotalParties {
		return nil, nil, errors.New("the number of received messages is not equal to total parties")
	}

	preSignatures := make([]*noninteractive.PreSignature, p.Tau)
	privateNoncePairs := make([]*noninteractive.PrivateNoncePair, p.Tau)
	for i := 0; i < p.Tau; i++ {
		preSignatures[i] = &noninteractive.PreSignature{
			DRowsAttested: make([]*noninteractive.AttestedCommitmentToNonce, len(p.CohortConfig.Participants)),
			ERowsAttested: make([]*noninteractive.AttestedCommitmentToNonce, len(p.CohortConfig.Participants)),
		}
		privateNoncePairs[i] = &noninteractive.PrivateNoncePair{
			D: p.state.dColumns[i],
			E: p.state.eColumns[i],
		}
	}

	for j, identityKey := range p.CohortConfig.Participants {
		senderShamirId := j + 1
		message, exists := round1output[identityKey]
		if !exists {
			return nil, nil, errors.Errorf("did not receive any message from shamir id %d", senderShamirId)
		}
		if p.Tau != len(message.DColumnsAttested) || p.Tau != len(message.EColumnsAttested) {
			return nil, nil, errors.Errorf("participant %d does not have the same number of presignature material in this ceremony", senderShamirId)
		}
		for i := 0; i < p.Tau; i++ {
			Dij := message.DColumnsAttested[j]
			Eij := message.EColumnsAttested[j]
			if !Dij.Attestor.PublicKey().Equal(Eij.Attestor.PublicKey()) {
				return nil, nil, errors.Errorf("inconsistent attestor key for i=%d and j=%d", i, j)
			}
			if err := Dij.Validate(p.CohortConfig); err != nil {
				return nil, nil, errors.Wrapf(err, "could not validate attestation at i=%d and j=%d", i, j)
			}
			if err := Eij.Validate(p.CohortConfig); err != nil {
				return nil, nil, errors.Wrapf(err, "could not validate attestation at i=%d and j=%d", i, j)
			}
			preSignatures[i].DRowsAttested[j] = Dij
			preSignatures[i].ERowsAttested[j] = Eij
		}
	}
	return preSignatures, privateNoncePairs, nil
}
