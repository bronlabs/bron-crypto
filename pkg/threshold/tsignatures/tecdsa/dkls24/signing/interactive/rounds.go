package interactive

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/signing"
)

func (ic *Cosigner) Round1() (*signing.Round1Broadcast, network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round1P2P], error) {
	// Validation
	if ic.Round != 1 {
		return nil, nil, errs.NewRound("Running round %d but cosigner expected round %d", 1, ic.Round)
	}

	outputBroadcast, outputP2P, err := signing.DoRound1(ic.Participant, ic.Protocol, ic.Quorum, ic.state)
	if err != nil {
		return nil, nil, err //nolint:wrapcheck // done deliberately to forward aborts
	}

	ic.Round++
	return outputBroadcast, outputP2P, nil
}

func (ic *Cosigner) Round2(round1outputBroadcast network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round1Broadcast], round1outputP2P network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round1P2P]) (*signing.Round2Broadcast, network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round2P2P], error) {
	// Validation, round 1 messages delegated to signing.DoRound2
	if ic.Round != 2 {
		return nil, nil, errs.NewRound("Running round %d but cosigner expected round %d", 2, ic.Round)
	}

	outputBroadcast, outputP2P, err := signing.DoRound2(ic.Participant, ic.Protocol, ic.Quorum, ic.state, round1outputBroadcast, round1outputP2P)
	if err != nil {
		return nil, nil, err //nolint:wrapcheck // done deliberately to forward aborts
	}

	ic.Round++
	return outputBroadcast, outputP2P, nil
}

func (ic *Cosigner) Round3(round2outputBroadcast network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round2Broadcast], round2outputP2P network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round2P2P], message []byte) (*dkls24.PartialSignature, error) {
	// Validation, round 2 messages delegated to signing.DoRound3Prologue
	if ic.Round != 3 {
		return nil, errs.NewRound("Running round %d but cosigner expected round %d", 3, ic.Round)
	}

	if err := signing.DoRound3Prologue(ic.Participant, ic.Protocol, ic.Quorum, ic.state, round2outputBroadcast, round2outputP2P); err != nil {
		return nil, err //nolint:wrapcheck // done deliberately to forward aborts
	}

	partialSignature, err := signing.DoRound3Epilogue(
		ic.Participant,
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
		return nil, err //nolint:wrapcheck // done deliberately to forward aborts
	}

	ic.Round++
	return partialSignature, nil
}
