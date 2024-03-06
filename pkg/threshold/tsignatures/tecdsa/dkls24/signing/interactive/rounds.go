package interactive

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/signing"
)

func (ic *Cosigner) Round1() (*signing.Round1Broadcast, network.RoundMessages[*signing.Round1P2P], error) {
	// Validation
	if err := ic.InRound(1); err != nil {
		return nil, nil, errs.Forward(err)
	}

	outputBroadcast, outputP2P, err := signing.DoRound1(&ic.Participant, ic.Protocol, ic.Quorum, ic.state)
	if err != nil {
		return nil, nil, err //nolint:wrapcheck // done deliberately to forward aborts
	}

	ic.NextRound()
	return outputBroadcast, outputP2P, nil
}

func (ic *Cosigner) Round2(round1outputBroadcast network.RoundMessages[*signing.Round1Broadcast], round1outputP2P network.RoundMessages[*signing.Round1P2P]) (*signing.Round2Broadcast, network.RoundMessages[*signing.Round2P2P], error) {
	// Validation, round 1 messages delegated to signing.DoRound2
	if err := ic.InRound(2); err != nil {
		return nil, nil, errs.Forward(err)
	}

	outputBroadcast, outputP2P, err := signing.DoRound2(&ic.Participant, ic.Protocol, ic.Quorum, ic.state, round1outputBroadcast, round1outputP2P)
	if err != nil {
		return nil, nil, err //nolint:wrapcheck // done deliberately to forward aborts
	}

	ic.NextRound()
	return outputBroadcast, outputP2P, nil
}

func (ic *Cosigner) Round3(round2outputBroadcast network.RoundMessages[*signing.Round2Broadcast], round2outputP2P network.RoundMessages[*signing.Round2P2P], message []byte) (*dkls24.PartialSignature, error) {
	// Validation, round 2 messages delegated to signing.DoRound3Prologue
	if err := ic.InRound(3); err != nil {
		return nil, errs.Forward(err)
	}

	if err := signing.DoRound3Prologue(&ic.Participant, ic.Protocol, ic.Quorum, ic.state, round2outputBroadcast, round2outputP2P); err != nil {
		return nil, errs.Forward(err)
	}

	partialSignature, err := signing.DoRound3Epilogue(
		&ic.Participant,
		ic.Protocol,
		ic.Quorum,
		message,
		ic.state.R_i,
		ic.state.Sk_i,
		ic.state.Phi_i,
		ic.state.Cu_i,
		ic.state.Cv_i,
		ic.state.Du_i,
		ic.state.Dv_i,
		ic.state.Psi_i,
		ic.state.ReceivedBigR_i,
	)
	if err != nil {
		return nil, errs.Forward(err)
	}

	ic.LastRound()
	return partialSignature, nil
}
