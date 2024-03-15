package noninteractive

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/signing"
)

func (p *PreGenParticipant) Round1() (*signing.Round1Broadcast, network.RoundMessages[*signing.Round1P2P], error) {
	// Validation
	if err := p.InRound(1); err != nil {
		return nil, nil, errs.WrapValidation(err, "Participant in invalid round")
	}

	outputBroadcast, outputP2P, err := signing.DoRound1(&p.Participant, p.Protocol(), p.Quorum, p.state)
	if err != nil {
		return nil, nil, err //nolint:wrapcheck // done deliberately to forward aborts
	}

	p.NextRound()
	return outputBroadcast, outputP2P, nil
}

func (p *PreGenParticipant) Round2(round1outputBroadcast network.RoundMessages[*signing.Round1Broadcast], round1outputP2P network.RoundMessages[*signing.Round1P2P]) (*signing.Round2Broadcast, network.RoundMessages[*signing.Round2P2P], error) {
	// Validation, round 1 messages delegated to signing.DoRound2
	if err := p.InRound(2); err != nil {
		return nil, nil, errs.WrapValidation(err, "Participant in invalid round")
	}

	outputBroadcast, outputP2P, err := signing.DoRound2(&p.Participant, p.Protocol(), p.Quorum, p.state, round1outputBroadcast, round1outputP2P)
	if err != nil {
		return nil, nil, err //nolint:wrapcheck // done deliberately to forward aborts
	}

	p.NextRound()
	return outputBroadcast, outputP2P, nil
}

func (p *PreGenParticipant) Round3(round2outputBroadcast network.RoundMessages[*signing.Round2Broadcast], round2outputP2P network.RoundMessages[*signing.Round2P2P]) (*dkls24.PreProcessingMaterial, error) {
	// Validation, round 2 messages delegated to signing.DoRound3Prologue
	if err := p.InRound(3); err != nil {
		return nil, errs.WrapValidation(err, "Participant in invalid round")
	}

	if err := signing.DoRound3Prologue(&p.Participant, p.Protocol(), p.Quorum, p.state, round2outputBroadcast, round2outputP2P); err != nil {
		return nil, err //nolint:wrapcheck // done deliberately to forward aborts
	}

	Rs := p.state.ReceivedBigR_i.Clone()
	Rs.Put(p.IdentityKey(), p.Curve().ScalarBaseMult(p.state.R_i))

	ppm := &dkls24.PreProcessingMaterial{
		PreSigners: p.Quorum,
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

	p.LastRound()
	return ppm, nil
}
