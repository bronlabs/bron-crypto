package interactive

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/network"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23/signing"
)

func (ic *Cosigner) Round1() (network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round1P2P], error) {
	// Validation
	if ic.Round != 1 {
		return nil, errs.NewRound("Running round %d but cosigner expected round %d", 1, ic.Round)
	}

	outputP2P, err := signing.DoRound1(ic.Participant, ic.Protocol)
	if err != nil {
		return nil, err //nolint:wrapcheck // done deliberately to forward aborts
	}

	ic.Round++
	return outputP2P, nil
}

func (ic *Cosigner) Round2(
	round1outputP2P network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round1P2P],
) (network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round2P2P], error) {
	// Validation
	if ic.Round != 2 {
		return nil, errs.NewRound("Running round %d but cosigner expected round %d", 2, ic.Round)
	}

	outputP2P, err := signing.DoRound2(ic.Participant, ic.Protocol, round1outputP2P)
	if err != nil {
		return nil, err //nolint:wrapcheck // done deliberately to forward aborts
	}

	ic.Round++
	return outputP2P, nil
}

func (ic *Cosigner) Round3(
	round2outputP2P network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round2P2P],
) (*signing.Round3Broadcast, network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round3P2P], error) {
	// Validation
	if ic.Round != 3 {
		return nil, nil, errs.NewRound("Running round %d but cosigner expected round %d", 3, ic.Round)
	}

	pairwiseSeeds, pairwiseBaseOTs, err := signing.DoRound3Prologue(ic.Participant, ic.Protocol, round2outputP2P)
	if err != nil {
		return nil, nil, err //nolint:wrapcheck // done deliberately to forward aborts
	}

	if err := ic.InitializeZeroShareSamplingParty(pairwiseSeeds); err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to initialise zero share sampling party")
	}

	if err := ic.InitializeMultipliers(pairwiseBaseOTs); err != nil {
		return nil, nil, errs.WrapFailed(err, "failed to initialise multipliers")
	}

	outputBroadcast, outputP2P, err := signing.DoRound3(ic.Participant, ic.Protocol, ic.state)
	if err != nil {
		return nil, nil, err //nolint:wrapcheck // done deliberately to forward aborts
	}

	ic.Round++
	return outputBroadcast, outputP2P, nil
}

func (ic *Cosigner) Round4(
	round3outputBroadcast network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round3Broadcast],
	round3outputP2P network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round3P2P],
) (*signing.Round4Broadcast, network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round4P2P], error) {
	// Validation, input round messages delegated to signing.DoRound2
	if ic.Round != 4 {
		return nil, nil, errs.NewRound("Running round %d but cosigner expected round %d", 4, ic.Round)
	}

	outputBroadcast, outputP2P, err := signing.DoRound4(ic.Participant, ic.Protocol, ic.state, round3outputBroadcast, round3outputP2P)
	if err != nil {
		return nil, nil, err //nolint:wrapcheck // done deliberately to forward aborts
	}

	ic.Round++
	return outputBroadcast, outputP2P, nil
}

func (ic *Cosigner) Round5(
	round4outputBroadcast network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round4Broadcast],
	round4outputP2P network.RoundMessages[types.ThresholdSignatureProtocol, *signing.Round4P2P],
	message []byte,
) (*dkls23.PartialSignature, error) {
	// Validation, input round messages delegated to signing.DoRound3Prologue
	if ic.Round != 5 {
		return nil, errs.NewRound("Running round %d but cosigner expected round %d", 5, ic.Round)
	}

	if err := signing.DoRound5Prologue(ic.Participant, ic.Protocol, ic.state, round4outputBroadcast, round4outputP2P); err != nil {
		return nil, err //nolint:wrapcheck // done deliberately to forward aborts
	}

	partialSignature, err := signing.DoRound5Epilogue(
		ic.Participant,
		ic.Protocol,
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
