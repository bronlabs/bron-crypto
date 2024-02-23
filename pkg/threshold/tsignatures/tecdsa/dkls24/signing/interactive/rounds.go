package interactiveSigning

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/signing"
)

func (ic *Cosigner) Round1() (*signing.Round1Broadcast, types.RoundMessages[*signing.Round1P2P], error) {
	if ic.round != 1 {
		return nil, nil, errs.NewRound("round mismatch %d != 1", ic.round)
	}

	outputBroadcast, outputP2P, err := signing.DoRound1(ic, ic.Protocol(), ic.Quorum, ic.state)
	if err != nil {
		return nil, nil, err //nolint:wrapcheck // done deliberately to forward aborts
	}

	ic.round++
	return outputBroadcast, outputP2P, nil
}

func (ic *Cosigner) Round2(round1outputBroadcast types.RoundMessages[*signing.Round1Broadcast], round1outputP2P types.RoundMessages[*signing.Round1P2P]) (*signing.Round2Broadcast, types.RoundMessages[*signing.Round2P2P], error) {
	if ic.round != 2 {
		return nil, nil, errs.NewRound("round mismatch %d != 2", ic.round)
	}

	outputBroadcast, outputP2P, err := signing.DoRound2(ic, ic.Protocol(), ic.Quorum, ic.state, round1outputBroadcast, round1outputP2P)
	if err != nil {
		return nil, nil, err //nolint:wrapcheck // done deliberately to forward aborts
	}

	ic.round++
	return outputBroadcast, outputP2P, nil
}

func (ic *Cosigner) Round3(round2outputBroadcast types.RoundMessages[*signing.Round2Broadcast], round2outputP2P types.RoundMessages[*signing.Round2P2P], message []byte) (*dkls24.PartialSignature, error) {
	if ic.round != 3 {
		return nil, errs.NewRound("round mismatch %d != 3", ic.round)
	}

	if err := signing.DoRound3Prologue(ic, ic.Protocol(), ic.Quorum, ic.state, round2outputBroadcast, round2outputP2P); err != nil {
		return nil, err //nolint:wrapcheck // done deliberately to forward aborts
	}

	partialSignature, err := signing.DoRound3Epilogue(
		ic,
		ic.Protocol(),
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

	ic.round++
	return partialSignature, nil
}
