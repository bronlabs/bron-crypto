package noninteractiveSigning

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/hjky"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/mult"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/signing"
)

type Round1Broadcast struct {
	BigR_i          []curves.Point
	ZeroShareOutput []*hjky.Round1Broadcast

	_ types.Incomparable
}

type Round1P2P struct {
	InstanceKeyCommitment []commitments.Commitment
	MultiplicationOutput  []*mult.Round1Output
	ZeroShareOutput       []*hjky.Round1P2P

	_ types.Incomparable
}

type Round2P2P struct {
	Multiplication     []*mult.Round2Output
	GammaU_ij          []curves.Point
	GammaV_ij          []curves.Point
	Psi_ij             []curves.Scalar
	InstanceKeyWitness []commitments.Witness

	_ types.Incomparable
}

type Round2Broadcast struct {
	Pk_i []curves.Point

	_ types.Incomparable
}

func (p *PreGenParticipant) Round1() (outputBroadcast *Round1Broadcast, outputUnicast map[types.IdentityHash]*Round1P2P, err error) {
	if p.round != 1 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 1", p.round)
	}

	r1bo := make([]*signing.Round1Broadcast, p.Tau)
	r1uo := make([]map[types.IdentityHash]*signing.Round1P2P, p.Tau)
	for t := 0; t < p.Tau; t++ {
		r1bo[t], r1uo[t], err = signing.DoRound1(p, p.CohortConfig.Participants, p.state[t])
		if err != nil {
			return nil, nil, err //nolint:wrapcheck // done deliberately to forward aborts
		}
	}

	outputBroadcast = &Round1Broadcast{
		BigR_i:          make([]curves.Point, p.Tau),
		ZeroShareOutput: make([]*hjky.Round1Broadcast, p.Tau),
	}
	for t := 0; t < p.Tau; t++ {
		outputBroadcast.BigR_i[t] = r1bo[t].BigR_i
		outputBroadcast.ZeroShareOutput[t] = r1bo[t].ZeroShareOutput
	}
	outputUnicast = make(map[types.IdentityHash]*Round1P2P)
	for idHash := range p.CohortConfig.Participants.Iter() {
		if idHash == p.MyAuthKey.Hash() {
			continue
		}
		outputUnicast[idHash] = &Round1P2P{
			InstanceKeyCommitment: make([]commitments.Commitment, p.Tau),
			MultiplicationOutput:  make([]*mult.Round1Output, p.Tau),
			ZeroShareOutput:       make([]*hjky.Round1P2P, p.Tau),
		}
		for t := 0; t < p.Tau; t++ {
			outputUnicast[idHash].InstanceKeyCommitment[t] = r1uo[t][idHash].InstanceKeyCommitment
			outputUnicast[idHash].MultiplicationOutput[t] = r1uo[t][idHash].MultiplicationOutput
			outputUnicast[idHash].ZeroShareOutput[t] = r1uo[t][idHash].ZeroShareOutput
		}
	}

	p.round++
	return outputBroadcast, outputUnicast, nil
}

func (p *PreGenParticipant) Round2(r1b map[types.IdentityHash]*Round1Broadcast, r1u map[types.IdentityHash]*Round1P2P) (*Round2Broadcast, map[types.IdentityHash]*Round2P2P, error) {
	if p.round != 2 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 2", p.round)
	}

	inputBroadcast := make([]map[types.IdentityHash]*signing.Round1Broadcast, p.Tau)
	inputUnicast := make([]map[types.IdentityHash]*signing.Round1P2P, p.Tau)
	for t := 0; t < p.Tau; t++ {
		inputBroadcast[t] = make(map[types.IdentityHash]*signing.Round1Broadcast)
		inputUnicast[t] = make(map[types.IdentityHash]*signing.Round1P2P)
		for idHash := range p.CohortConfig.Participants.Iter() {
			if idHash == p.MyAuthKey.Hash() {
				continue
			}
			inputBroadcast[t][idHash] = &signing.Round1Broadcast{
				BigR_i:          r1b[idHash].BigR_i[t],
				ZeroShareOutput: r1b[idHash].ZeroShareOutput[t],
			}
			inputUnicast[t][idHash] = &signing.Round1P2P{
				InstanceKeyCommitment: r1u[idHash].InstanceKeyCommitment[t],
				MultiplicationOutput:  r1u[idHash].MultiplicationOutput[t],
				ZeroShareOutput:       r1u[idHash].ZeroShareOutput[t],
			}
		}
	}

	r2bo := make([]*signing.Round2Broadcast, p.Tau)
	r2uo := make([]map[types.IdentityHash]*signing.Round2P2P, p.Tau)
	for t := 0; t < p.Tau; t++ {
		var err error
		r2bo[t], r2uo[t], err = signing.DoRound2(p, p.CohortConfig.Participants, p.state[t], inputBroadcast[t], inputUnicast[t])
		if err != nil {
			//nolint:wrapcheck // done deliberately to forward aborts
			return nil, nil, err
		}
	}

	outputBroadcast := &Round2Broadcast{
		Pk_i: make([]curves.Point, p.Tau),
	}
	for t := 0; t < p.Tau; t++ {
		outputBroadcast.Pk_i[t] = r2bo[t].Pk_i
	}
	outputUnicast := make(map[types.IdentityHash]*Round2P2P)
	for idHash := range p.CohortConfig.Participants.Iter() {
		if idHash == p.MyAuthKey.Hash() {
			continue
		}
		outputUnicast[idHash] = &Round2P2P{
			Multiplication:     make([]*mult.Round2Output, p.Tau),
			GammaU_ij:          make([]curves.Point, p.Tau),
			GammaV_ij:          make([]curves.Point, p.Tau),
			Psi_ij:             make([]curves.Scalar, p.Tau),
			InstanceKeyWitness: make([]commitments.Witness, p.Tau),
		}
		for t := 0; t < p.Tau; t++ {
			outputUnicast[idHash].Multiplication[t] = r2uo[t][idHash].Multiplication
			outputUnicast[idHash].GammaU_ij[t] = r2uo[t][idHash].GammaU_ij
			outputUnicast[idHash].GammaV_ij[t] = r2uo[t][idHash].GammaV_ij
			outputUnicast[idHash].Psi_ij[t] = r2uo[t][idHash].Psi_ij
			outputUnicast[idHash].InstanceKeyWitness[t] = r2uo[t][idHash].InstanceKeyWitness
		}
	}

	p.round++
	return outputBroadcast, outputUnicast, nil
}

func (p *PreGenParticipant) Round3(r2ob map[types.IdentityHash]*Round2Broadcast, r2ou map[types.IdentityHash]*Round2P2P) (*dkls24.PreSignatureBatch, error) {
	if p.round != 3 {
		return nil, errs.NewInvalidRound("round mismatch %d != 3", p.round)
	}

	inputBroadcast := make([]map[types.IdentityHash]*signing.Round2Broadcast, p.Tau)
	inputUnicast := make([]map[types.IdentityHash]*signing.Round2P2P, p.Tau)
	for t := 0; t < p.Tau; t++ {
		inputBroadcast[t] = make(map[types.IdentityHash]*signing.Round2Broadcast)
		inputUnicast[t] = make(map[types.IdentityHash]*signing.Round2P2P)
		for idHash := range p.CohortConfig.Participants.Iter() {
			if idHash == p.MyAuthKey.Hash() {
				continue
			}
			inputBroadcast[t][idHash] = &signing.Round2Broadcast{
				Pk_i: r2ob[idHash].Pk_i[t],
			}
			inputUnicast[t][idHash] = &signing.Round2P2P{
				Multiplication:     r2ou[idHash].Multiplication[t],
				GammaU_ij:          r2ou[idHash].GammaU_ij[t],
				GammaV_ij:          r2ou[idHash].GammaV_ij[t],
				Psi_ij:             r2ou[idHash].Psi_ij[t],
				InstanceKeyWitness: r2ou[idHash].InstanceKeyWitness[t],
			}
		}
	}

	for t := 0; t < p.Tau; t++ {
		if err := signing.DoRound3Prologue(p, p.CohortConfig.Participants, p.state[t], inputBroadcast[t], inputUnicast[t]); err != nil {
			return nil, err //nolint:wrapcheck // done deliberately to forward aborts
		}
	}

	preSignatureBatch := &dkls24.PreSignatureBatch{
		PreSignatures: make([]*dkls24.PreSignature, p.Tau),
	}
	for t := 0; t < p.Tau; t++ {
		preSignatureBatch.PreSignatures[t] = &dkls24.PreSignature{
			Cu:        p.state[t].Cu_i,
			Cv:        p.state[t].Cv_i,
			Du:        p.state[t].Du_i,
			Dv:        p.state[t].Dv_i,
			Phi:       p.state[t].Phi_i,
			Psi:       p.state[t].Psi_i,
			R:         p.state[t].R_i,
			TheirBigR: p.state[t].ReceivedBigR_i,
			Zeta:      p.state[t].Zeta_i,
		}
	}

	p.round++
	return preSignatureBatch, nil
}
