package softspoken

import (
	"crypto/rand"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
)

// Round1Output is the receiver's PUBLIC output of round1 of OTe/COTe, to be sent to the Sender.
type Round1Output struct {
	// expansionMask (u^i) ∈ [κ][ξ']bits is the expanded and masked PRG outputs
	expansionMask ExpansionMask
	// challengeResponse is the challenge response for the consistency,
	// containing ẋ ∈ [σ]bits, ṫ ∈ [κ][σ]bits
	challengeResponse ChallengeResponse
}

// Round1Extend uses the PRG to extend the baseOT seeds, then proves consistency of the extension.
func (receiver *Receiver) Round1ExtendAndProveConsistency(
	oTeInputChoices *OTeInputChoices, // x_i ∈ [ξ]bits
) (extPackedChoices *ExtPackedChoices, // x_i ∈ [ξ']bits
	oTeReceiverOutput *OTeReceiverOutput, // v_x ∈ [ξ][ω][κ]bits
	round1Output *Round1Output, // u_i ∈ [κ][ξ']bits, ẋ ∈ [σ]bits, ṫ ∈ [κ][σ]bits
	err error,
) {
	round1Output = &Round1Output{}

	// Sanitise inputs
	if oTeInputChoices == nil {
		return nil, nil, nil, errs.NewInvalidArgument("nil (oTeInputChoices) in input arguments of Round1ExtendAndProveConsistency")
	}

	// (Ext.1) Store the input choices and fill the rest with random values
	extPackedChoices = &ExtPackedChoices{}
	copy(extPackedChoices[:ZetaBytes], (*oTeInputChoices)[:])
	if _, err = rand.Read(extPackedChoices[ZetaBytes:]); err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "sampling random bits for Softspoken OTe (Ext.1)")
	}
	// (Ext.2) Expand the baseOT results using them as seed to the PRG
	extOptions := &ExtOptions{}
	for i := 0; i < Kappa; i++ {
		// k^i_0 --(PRG)--> t^i_0
		err = PRG(receiver.uniqueSessionId, receiver.baseOtSeeds.OneTimePadEncryptionKeys[i][0][:],
			extOptions[0][i][:])
		if err != nil {
			return nil, nil, nil, errs.WrapFailed(err, "bad PRG for SoftSpoken OTe (Ext.2)")
		}
		// k^i_1 --(PRG)--> t^i_1
		err = PRG(receiver.uniqueSessionId, receiver.baseOtSeeds.OneTimePadEncryptionKeys[i][1][:],
			extOptions[1][i][:])
		if err != nil {
			return nil, nil, nil, errs.WrapFailed(err, "bad PRG for SoftSpoken OTe (Ext.2)")
		}
	}
	// (Ext.3) Compute u_i and send it
	for i := 0; i < Kappa; i++ {
		for j := 0; j < ZetaPrimeBytes; j++ {
			round1Output.expansionMask[i][j] = extOptions[0][i][j] ^ extOptions[1][i][j] ^ extPackedChoices[j]
		}
	}

	// (*)(Fiat-Shamir): Append the expansionMask to the transcript
	for i := 0; i < Kappa; i++ {
		receiver.transcript.AppendMessages("OTe_expansionMask", round1Output.expansionMask[i][:])
	}

	// (Check.1) Generate the challenge (χ) using Fiat-Shamir heuristic
	challengeFiatShamir := &Challenge{}
	for i := 0; i < M; i++ {
		copy(challengeFiatShamir[i][:], receiver.transcript.ExtractBytes("OTe_challenge_Chi", SigmaBytes))
	}
	// (Check.2) Compute ẋ and ṫ
	receiver.ComputeChallengeResponse(extPackedChoices, extOptions, challengeFiatShamir, &round1Output.challengeResponse)

	// (T&R.1) Transpose t^i_0 into t_j
	t_j := transposeBooleanMatrix(&extOptions[0]) // t_j ∈ [ξ'][κ]bits
	// (T&R.2) Hash ξ rows of t_j using the index as salt (drop ξ' - ξ rows, used for consistency check)
	oTeReceiverOutput = &OTeReceiverOutput{}
	err = HashSalted(&receiver.uniqueSessionId, t_j[:], oTeReceiverOutput[:])
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "bad hashing t_j for SoftSpoken COTe (T&R.2)")
	}

	// (*)(Fiat-Shamir): Append the challenge response to the transcript
	receiver.transcript.AppendMessages("OTe_challengeResponse_x_val", round1Output.challengeResponse.x_val[:])
	for i := 0; i < Kappa; i++ {
		receiver.transcript.AppendMessages("OTe_challengeResponse_t_val", round1Output.challengeResponse.t_val[i][:])
	}
	return extPackedChoices, oTeReceiverOutput, round1Output, nil
}

// Round2Output is the sender's PUBLIC output of round2 of OTe/COTe, to be sent to the Receiver.
type Round2Output struct {
	derandomizeMasks []DerandomizeMask
}

// Round2Extend uses the PRG to extend the baseOT results, verifies their consistency
// and derandomizes them (COTe only).
func (sender *Sender) Round2ExtendAndCheckConsistency(
	round1Output *Round1Output,
	InputOpts []COTeInputOpt, // Input opts (α) ∈ [ξ]curve.Scalar. Set to nil for OTe.
) (oTeSenderOutput *OTeSenderOutput, cOTeSenderOutputs []COTeSenderOutput, round2Output *Round2Output, err error) {
	// Sanitise inputs
	if round1Output == nil {
		return nil, nil, nil, errs.NewInvalidArgument("nil (round1Output) in input arguments of Round2ExtendAndCheckConsistency")
	}

	// (Ext.2) Expand the baseOT results using them as seed to the PRG
	extChosenOpt := ExtDeltaOpt{}
	for i := 0; i < Kappa; i++ {
		// This is the core expansion of the OT: k^i_{Δ_i} --(PRG)--> t^i_{Δ_i}
		if err := PRG(sender.uniqueSessionId,
			sender.baseOtSeeds.OneTimePadDecryptionKey[i][:],
			extChosenOpt[i][:]); err != nil {
			return nil, nil, nil, errs.WrapFailed(err, "prg failed")
		}
	}

	// (Ext.4) Compute q_i = Δ_i • u_i + t_i (constant time)
	extCorrelations := ExtCorrelations{}
	for i := 0; i < Kappa; i++ {
		for j := 0; j < ZetaPrimeBytes; j++ {
			qiTemp := round1Output.expansionMask[i][j] ^ extChosenOpt[i][j]
			if sender.baseOtSeeds.RandomChoiceBits[i] != 0 {
				extCorrelations[i][j] = qiTemp
			} else {
				extCorrelations[i][j] = extChosenOpt[i][j]
			}
		}
	}

	// (T&R.1, T&R.3) Transpose and Randomise the correlations (q^i -> v_0 and q^i+Δ -> v_1)
	// (T&R.1) Transpose q^i -> q_j and q^i+Δ -> q_j+Δ
	extCorrelationsTransposed := transposeBooleanMatrix(&extCorrelations) // q_j ∈ [ξ'][κ]bits
	var extCorrelationsTransposedPlusDelta [Zeta][KappaBytes]byte
	for i := 0; i < KappaBytes; i++ {
		Delta := sender.baseOtSeeds.PackedRandomChoiceBits[i]
		for j := 0; j < Zeta; j++ { // drop ξ' - ξ rows, used for consistency check
			extCorrelationsTransposedPlusDelta[j][i] = extCorrelationsTransposed[j][i] ^ Delta
		}
	}
	// (T&R.3) Randomise by hashing the first ξ rows of q_j and q_j+Δ (drop ξ' - ξ rows, used for consistency check)
	oTeSenderOutput = &OTeSenderOutput{}
	err = HashSalted(&sender.uniqueSessionId, extCorrelationsTransposed[:Zeta], oTeSenderOutput[0][:])
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "bad hashing q_j for SoftSpoken COTe (T&R.3)")
	}
	err = HashSalted(&sender.uniqueSessionId, extCorrelationsTransposedPlusDelta[:], oTeSenderOutput[1][:])
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "bad hashing q_j_pDelta for SoftSpoken COTe (T&R.3)")
	}

	// (*)(Fiat-Shamir): Append the expansionMask to the transcript
	for i := 0; i < Kappa; i++ {
		sender.transcript.AppendMessages("OTe_expansionMask", round1Output.expansionMask[i][:])
	}

	// (Check.1) Generate the challenge (χ) using Fiat-Shamir heuristic
	challengeFiatShamir := &Challenge{}
	for i := 0; i < M; i++ {
		copy(challengeFiatShamir[i][:], sender.transcript.ExtractBytes("OTe_challenge_Chi", SigmaBytes))
	}
	// (Check.3) Check the consistency of the challenge response computing q^i
	err = sender.CheckConsistency(challengeFiatShamir, &round1Output.challengeResponse, &extCorrelations)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "bad consistency check for SoftSpoken COTe (Check.3)")
	}

	// (*)(Fiat-Shamir): Append the challenge response to the transcript
	sender.transcript.AppendMessages("OTe_challengeResponse_x_val", round1Output.challengeResponse.x_val[:])
	for i := 0; i < Kappa; i++ {
		sender.transcript.AppendMessages("OTe_challengeResponse_t_val", round1Output.challengeResponse.t_val[i][:])
	}

	// Return OTe and avoid derandomizing if the input opts are not provided
	if InputOpts == nil {
		return oTeSenderOutput, nil, nil, nil
	}

	// (Derand.1) Compute the derandomization mask τ and the correlation z_A
	round2Output = &Round2Output{}
	L := len(InputOpts) // Number of reuses of the output OTe batch.
	if sender.useForcedReuse {
		cOTeSenderOutputs = make([]COTeSenderOutput, L)
		round2Output.derandomizeMasks = make([]DerandomizeMask, L)
		err = sender.ComputeDerandomizeMaskForcedReuse(
			oTeSenderOutput, InputOpts, &cOTeSenderOutputs, &round2Output.derandomizeMasks)
		if err != nil {
			return nil, nil, nil, errs.WrapFailed(err, "bad forced-reuse derandomization for SoftSpoken COTe (Derand.1)")
		}
	} else {
		if L != 1 { // If not forced reuse, L must be 1
			return nil, nil, nil, errs.NewInvalidArgument("InputOpts length != 1. Set useForcedReuse, or set a higher value of L, or loop over the InputOpts")
		}
		cOTeSenderOutputs = make([]COTeSenderOutput, 1)
		round2Output.derandomizeMasks = make([]DerandomizeMask, 1)
		err = sender.ComputeDerandomizeMask(oTeSenderOutput, &InputOpts[0],
			&cOTeSenderOutputs[0], &round2Output.derandomizeMasks[0])
		if err != nil {
			return nil, nil, nil, errs.WrapFailed(err, "bad derandomization for SoftSpoken COTe (Derand.1)")
		}
	}

	// (*)(Fiat-Shamir): Append the derandomization mask to the transcript
	for batchIndex := 0; batchIndex < len(round2Output.derandomizeMasks); batchIndex++ {
		for i := 0; i < Zeta; i++ {
			sender.transcript.AppendScalars("OTe_derandomizeMask", round2Output.derandomizeMasks[batchIndex][i][:]...)
		}
	}

	return oTeSenderOutput, cOTeSenderOutputs, round2Output, nil
}

// Round3Derandomize uses the derandomization mask to derandomize the COTe output.
func (receiver *Receiver) Round3Derandomize(
	round2Output *Round2Output,
	extPackedChoices *ExtPackedChoices,
	oTeReceiverOutput *OTeReceiverOutput,
) (cOTeReceiverOutput []COTeReceiverOutput, err error) {
	// Sanitise input
	if (round2Output == nil) || (extPackedChoices == nil) || (oTeReceiverOutput == nil) {
		return nil, errs.NewInvalidArgument("nil in input arguments of Round3Derandomize")
	}

	// (*)(Fiat-Shamir): Append the derandomization mask to the transcript
	L := len(round2Output.derandomizeMasks) // Number of reuses of the output OTe batch.
	for batchIndex := 0; batchIndex < L; batchIndex++ {
		for i := 0; i < Zeta; i++ {
			receiver.transcript.AppendScalars("OTe_derandomizeMask", round2Output.derandomizeMasks[batchIndex][i][:]...)
		}
	}

	// (Derand.2) Apply derandomize Mask to the OTe output
	if receiver.useForcedReuse {
		cOTeReceiverOutput, err = receiver.DerandomizeForcedReuse(oTeReceiverOutput, extPackedChoices, round2Output.derandomizeMasks)
		if err != nil {
			return nil, errs.WrapFailed(err, "bad forced-reuse derandomization for SoftSpoken COTe (Derand.2)")
		}
	} else {
		if L != 1 {
			return nil, errs.NewInvalidArgument("derandomizeMasks length must be 1 unless forced reuse is set. Alternatively, set a higher value of L or loop over the derandomizeMasks")
		}
		cOTeReceiverOutput = make([]COTeReceiverOutput, 1)
		err = receiver.Derandomize(oTeReceiverOutput, &round2Output.derandomizeMasks[0], extPackedChoices, &cOTeReceiverOutput[0])
		if err != nil {
			return nil, errs.WrapFailed(err, "bad derandomization for SoftSpoken COTe (Derand.2)")
		}
	}
	return cOTeReceiverOutput, nil
}

// -------------------------------------------------------------------------- //
// ---------------------------- INDIVIDUAL STEPS ---------------------------- //
// -------------------------------------------------------------------------- //
// (Check.2) Compute the challenge response ẋ, ṫ^i ∀i∈[κ].
func (*Receiver) ComputeChallengeResponse(extPackedChoices *ExtPackedChoices, extOptions *ExtOptions, challenge *Challenge, challengeResponse *ChallengeResponse) {
	// 		ẋ = x̂_{m+1} ...
	copy(challengeResponse.x_val[:], extPackedChoices[ZetaBytes:ZetaBytes+SigmaBytes])
	// 		                ... + Σ{j=1}^{m} χ_j • x̂_j
	for j := 0; j < M; j++ {
		x_hat_j := extPackedChoices[j*SigmaBytes : (j+1)*SigmaBytes]
		Chi_j := challenge[j][:]
		for k := 0; k < SigmaBytes; k++ {
			challengeResponse.x_val[k] ^= (Chi_j[k] & x_hat_j[k])
		}
	}
	// 		ṫ^i = ...
	for i := 0; i < Kappa; i++ {
		//         ... t^i_hat_{m+1} ...
		copy(challengeResponse.t_val[i][:], extOptions[0][i][ZetaBytes:ZetaBytes+SigmaBytes])
		//                           ... + Σ{j=1}^{m} χ_j • t^i_hat_j
		for j := 0; j < M; j++ {
			t_hat_j := extOptions[0][i][j*SigmaBytes : (j+1)*SigmaBytes]
			Chi_j := challenge[j][:]
			for k := 0; k < SigmaBytes; k++ {
				challengeResponse.t_val[i][k] ^= (Chi_j[k] & t_hat_j[k])
			}
		}
	}
}

// (Check.3) CheckConsistency checks the consistency of the extension using the challenge response.
func (sender *Sender) CheckConsistency(
	challenge *Challenge,
	challengeResponse *ChallengeResponse,
	extCorrelations *ExtCorrelations,
) error {
	qi_val := [SigmaBytes]byte{}
	var q_expected, qi_sum byte
	for i := 0; i < Kappa; i++ {
		// q̇^i = q^i_hat_{m+1} ...
		copy(qi_val[:], extCorrelations[i][ZetaBytes:ZetaBytes+SigmaBytes])
		//                     ... + Σ{j=1}^{m} χ_j • q^i_hat_j
		for j := 0; j < M; j++ {
			qi_hat_j := extCorrelations[i][j*SigmaBytes : (j+1)*SigmaBytes]
			Chi_j := challenge[j][:]
			for k := 0; k < SigmaBytes; k++ {
				qi_val[k] ^= (qi_hat_j[k] & Chi_j[k])
			}
		}
		// ABORT if q̇^i != ṫ^i + Δ_i • ẋ  ∀ i ∈[κ]
		for k := 0; k < SigmaBytes; k++ {
			qi_sum = challengeResponse.t_val[i][k] ^ challengeResponse.x_val[k]
			if sender.baseOtSeeds.RandomChoiceBits[i] != 0 {
				q_expected = qi_sum
			} else {
				q_expected = challengeResponse.t_val[i][k]
			}
			if !(q_expected == qi_val[k]) {
				return errs.NewIdentifiableAbort("q_val != q_expected in SoftspokenOT. OTe consistency check failed")
			}
		}
	}
	return nil
}

// (Derand.1) Derandomize (z_A) by mapping to curve points, establishing the
// correlation and creating the derandomization mask.
func (sender *Sender) ComputeDerandomizeMask(
	oTeSenderOutput *OTeSenderOutput,
	InputOpts *COTeInputOpt,
	cOTeSenderOutput *COTeSenderOutput,
	derandomizeMask *DerandomizeMask,
) (err error) {
	for j := 0; j < Zeta; j++ {
		for k := 0; k < OTeWidth; k++ {
			// z_A_j = ECP(v_0_j)
			cOTeSenderOutput[j][k], err = sender.curve.Scalar.SetBytes(oTeSenderOutput[0][j][k][:])
			if err != nil {
				return errs.WrapFailed(err, "bad v_0 mapping to curve elements (Derand.1)")
			}
			// τ_j = ECP(v_1_j) - z_A_j + α_j
			derandomizeMask[j][k], err = sender.curve.Scalar.SetBytes(oTeSenderOutput[1][j][k][:])
			if err != nil {
				return errs.WrapFailed(err, "bad v_1 mapping to curve elements (Derand.1)")
			}
			derandomizeMask[j][k] = derandomizeMask[j][k].Sub(cOTeSenderOutput[j][k]).Add(InputOpts[j][k])
		}
	}
	return nil
}

// (Derand.1[Forced-Reuse]) Derandomize (z_A) by mapping to curve points, establishing
// the correlation and creating the derandomization mask. The force-reuse version
// applies the same OTe output batch to all the input opts.
func (sender *Sender) ComputeDerandomizeMaskForcedReuse(
	oTeSenderOutput *OTeSenderOutput,
	inputOpts []COTeInputOpt,
	cOTeSenderOutputs *[]COTeSenderOutput,
	derandomizeMasks *[]DerandomizeMask,
) (err error) {
	inputBatchLen := len(inputOpts)
	for k := 0; k < inputBatchLen; k++ {
		// Apply the same OTe batch to all the inputs
		err = sender.ComputeDerandomizeMask(oTeSenderOutput, &inputOpts[k], &(*cOTeSenderOutputs)[k], &(*derandomizeMasks)[k])
		if err != nil {
			return errs.WrapFailed(err, "bad Sender Forced Reuse derandomization (Derand.1)")
		}
	}
	return nil
}

// (Derand.2) Derandomize using the mask (τ) to obtain the COTe receiver output (z_B).
// (constant time).
func (receiver *Receiver) Derandomize(
	oTeReceiverOutput *OTeReceiverOutput,
	derandomizeMask *DerandomizeMask,
	extPackChoices *ExtPackedChoices,
	cOTeReceiverOutput *COTeReceiverOutput,
) (err error) {
	var v_x_NegCurve, v_x_curve_corr curves.Scalar
	for j := 0; j < Zeta; j++ {
		for k := 0; k < OTeWidth; k++ {
			// ECP(v_x_j)
			v_x_NegCurve, err = receiver.curve.Scalar.SetBytes(oTeReceiverOutput[j][k][:])
			if err != nil {
				return errs.WrapFailed(err, "bad v_x mapping to curve elements (Derand.1)")
			}
			v_x_NegCurve = v_x_NegCurve.Neg()
			v_x_curve_corr = derandomizeMask[j][k].Add(v_x_NegCurve)
			if bitstring.SelectBit(extPackChoices[:], j) != 0 {
				// z_B_j = τ_j - ECP(v_x_j)  if x_j == 1
				cOTeReceiverOutput[j][k] = v_x_curve_corr
			} else {
				//       =     - ECP(v_x_j)  if x_j == 0
				cOTeReceiverOutput[j][k] = v_x_NegCurve
			}
		}
	}
	return nil
}

// (Derand.2[ForcedReuse]) Derandomize using the mask (τ) to obtain the COTe
// receiver output (z_B). The force-reuse version applies the same OTe output
// batch to all the input opts.
func (receiver *Receiver) DerandomizeForcedReuse(
	oTeReceiverOutput *OTeReceiverOutput,
	inputExtPackChoices *ExtPackedChoices,
	derandomizeMasks []DerandomizeMask,
) (cOTeReceiverOutput []COTeReceiverOutput, err error) {
	inputBatchLen := len(derandomizeMasks)
	cOTeReceiverOutput = make([]COTeReceiverOutput, len(derandomizeMasks))
	for k := 0; k < inputBatchLen; k++ {
		// Apply the same OTe batch to all the masks
		err = receiver.Derandomize(oTeReceiverOutput, &derandomizeMasks[k], inputExtPackChoices, &cOTeReceiverOutput[k])
		if err != nil {
			return nil, errs.WrapFailed(err, "bad Receiver Forced-Reuse derandomization (Derand.2)")
		}
	}
	return cOTeReceiverOutput, nil
}
