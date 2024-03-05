package noninteractive

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/signing"
)

func (p *PreGenParticipant) Round1() (*signing.Round1Broadcast, types.RoundMessages[*signing.Round1P2P], error) {
	if p.round != 1 {
		return nil, nil, errs.NewRound("round mismatch %d != 1", p.round)
	}

	outputBroadcast, outputP2P, err := signing.DoRound1(p, p.Protocol(), p.PreSigners, p.state)
	if err != nil {
		return nil, nil, err //nolint:wrapcheck // done deliberately to forward aborts
	}

	p.round++
	return outputBroadcast, outputP2P, nil
}

func (p *PreGenParticipant) Round2(round1outputBroadcast types.RoundMessages[*signing.Round1Broadcast], round1outputP2P types.RoundMessages[*signing.Round1P2P]) (*signing.Round2Broadcast, types.RoundMessages[*signing.Round2P2P], error) {
	if p.round != 2 {
		return nil, nil, errs.NewRound("round mismatch %d != 2", p.round)
	}

	outputBroadcast, outputP2P, err := signing.DoRound2(p, p.Protocol(), p.PreSigners, p.state, round1outputBroadcast, round1outputP2P)
	if err != nil {
		return nil, nil, err //nolint:wrapcheck // done deliberately to forward aborts
	}

	p.round++
	return outputBroadcast, outputP2P, nil
}

func (p *PreGenParticipant) Round3(round2outputBroadcast types.RoundMessages[*signing.Round2Broadcast], round2outputP2P types.RoundMessages[*signing.Round2P2P]) (*dkls24.PreProcessingMaterial, error) {
	if p.round != 3 {
		return nil, errs.NewRound("round mismatch %d != 3", p.round)
	}

	if err := signing.DoRound3Prologue(p, p.Protocol(), p.PreSigners, p.state, round2outputBroadcast, round2outputP2P); err != nil {
		return nil, err //nolint:wrapcheck // done deliberately to forward aborts
	}

	Rs := p.state.ReceivedBigR_i.Clone()
	Rs.Put(p.IdentityKey(), p.protocol.Curve().ScalarBaseMult(p.state.R_i))

	ppm := &dkls24.PreProcessingMaterial{
		PreSigners: p.PreSigners,
		PrivateMaterial: &dkls24.PrivatePreProcessingMaterial{
			Cu:   p.state.Cu_i,
			Cv:   p.state.Cv_i,
			Du:   p.state.Du_i,
			Dv:   p.state.Dv_i,
			Phi:  p.state.Phi_i,
			Psi:  p.state.Psi_i,
			R:    p.state.R_i,
			Zeta: p.state.Zeta_i,
		},
		PreSignature: Rs,
	}

	p.round++
	return ppm, nil
}
