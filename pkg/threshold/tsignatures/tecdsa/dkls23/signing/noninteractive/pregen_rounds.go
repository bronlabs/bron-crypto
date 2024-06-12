package noninteractive

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23/signing"
)

func (p *PreGenParticipant) Round1() (*signing.Round1Broadcast, network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round1P2P], error) {
	// Validation
	if p.Round != 1 {
		return nil, nil, errs.NewRound("Running round %d but participant expected round %d", 1, p.Round)
	}

	outputBroadcast, outputP2P, err := signing.DoRound1(&p.Participant, p.Protocol, p.Quorum, p.state)
	if err != nil {
		return nil, nil, err //nolint:wrapcheck // done deliberately to forward aborts
	}

	p.Round++
	return outputBroadcast, outputP2P, nil
}

func (p *PreGenParticipant) Round2(
	round1outputBroadcast network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round1Broadcast],
	round1outputP2P network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round1P2P],
) (*signing.Round2Broadcast, network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round2P2P], error) {
	// Validation, input messages delegated to signing.DoRound2
	if p.Round != 2 {
		return nil, nil, errs.NewRound("Running round %d but participant expected round %d", 2, p.Round)
	}

	outputBroadcast, outputP2P, err := signing.DoRound2(&p.Participant, p.Protocol, p.Quorum, p.state, round1outputBroadcast, round1outputP2P)
	if err != nil {
		return nil, nil, err //nolint:wrapcheck // done deliberately to forward aborts
	}

	p.Round++
	return outputBroadcast, outputP2P, nil
}

func (p *PreGenParticipant) Round3(
	round2outputBroadcast network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round2Broadcast],
	round2outputP2P network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round2P2P],
) (*dkls23.PreProcessingMaterial, error) {
	// Validation, input messages delegated to signing.DoRound3Prologue
	if p.Round != 3 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 3, p.Round)
	}

	if err := signing.DoRound3Prologue(&p.Participant, p.Protocol, p.Quorum, p.state, round2outputBroadcast, round2outputP2P); err != nil {
		return nil, err //nolint:wrapcheck // done deliberately to forward aborts
	}

	Rs := p.state.ReceivedBigR_i.Clone()
	Rs.Put(p.IdentityKey(), p.Protocol.Curve().ScalarBaseMult(p.state.R_i))

	ppm := &dkls23.PreProcessingMaterial{
		PreSigners: p.Quorum,
		PrivateMaterial: &dkls23.PrivatePreProcessingMaterial{
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

	p.Round++
	return ppm, nil
}
