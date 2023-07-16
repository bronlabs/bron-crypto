// Copyright Copper.co; All Rights Reserved.
//
// Package softspoken implements of maliciously secure 1-out-of-2 Correlated
//  Oblivious Transfer extension (COTe) protocol. We follow the designs from
//  [SoftSpokenOT](https://eprint.iacr.org/2022/192), alongside a derandomization
//  from [MR19](https://eprint.iacr.org/2019/706). For the protocol description
//  we use the notation from ROT^{κ,l} from [KOS15](https://eprint.iacr.org/2015/546)
// (Figure 10). The protocol is described in "protocol.go". We implement the
// "COTE with Fiat-Shamir" version, substituting the coin tossing required for
// the consistency check with the Fiat-Shamir heuristic (hash of the public transcript)
//

// OBLIVIOUS TRANSFER (OT)
// At high level, a single 1-out-of-2 OT realizes this functionality:
//  ┌------┐                      ┌------------------┐               ┌--------┐
//  |      |                      |                  |               |        |
//  |      |--> (Opt_0, Opt_1) -->|      1|2  OT     | <--(Choice)<--|        |
//  |Sender|                      |                  |               |Receiver|
//  |      |                      └------------------┘               |        |
//  |      |                               └-------> (DeltaOpt) -->  |        |
//  └------┘                                                         └--------┘
// s.t. DeltaOpt = Opt_{Choice} = Opt_0 • (1-Choice) + Opt_1 • Choice
//
// CORRELATED OBLIVIOUS TRANSFER (COT)
// In contrast, a single "Correlated" OT realizes tbe following functionality:
//  ┌------┐                      ┌------------------┐               ┌--------┐
//  |      |                      |                  |               |        |
//  |      |----> (InputOpt) ---->|      1|2  COT    | <--(Choice)<--|        |
//  |Sender|                      |                  |               |Receiver|
//  |      |                      └------------------┘               |        |
//  |      | <----- (Correlation) <--------┴-------> (DeltaOpt) ---> |        |
//  └------┘                                                         └--------┘
//  s.t. Correlation = Choice • InputOpt - DeltaOpt
//
// The Options, DeltaOpt and Correlation are elements of a group (e.g. Z_2,
// Z_{2^N}, F_q, elliptic curve points), whereas Choice is always a bit.
//
// OT EXTENSION (OTe, COTe)
// An "Extension" (both for OT and COT with Options of length κ) makes use of a
// PRG to expand each block of κ Base OTs  into L = n*κ OTs.

package softspoken

import (
	"crypto/rand"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
)

type (
	// ---------------------------- EXTENSION ------------------------------- //
	// ExpansionMask (u_i) ∈ [κ][η']bits is the expanded and masked PRG outputs
	ExpansionMask [Kappa][EtaPrimeBytes]byte

	// OTeInputChoices (x_i) ∈ [η]bits are the choice bits for the OTe.
	OTeInputChoices [EtaBytes]byte

	// ExtPackedChoices (x_i) ∈ [η']bits are the choice bits for the OTe filled with σ random values.
	ExtPackedChoices [EtaPrimeBytes]byte

	// ExtOptions (t^i_0, t^i_1) ∈ [2][κ][η]bits are expansions of BaseOT results using a PRG.
	ExtOptions [2][Kappa][EtaPrimeBytes]byte

	// ExtDeltaOpt (t^i_{Δ_i}) ∈ [κ][η]bits are the extended (via a PRG) baseOT deltaOpts.
	ExtDeltaOpt [Kappa][EtaPrimeBytes]byte

	// ExtCorrelations (q_i) ∈ [κ][η]bits are the extended correlations, q^i = Δ_i • x + t^i
	ExtCorrelations [Kappa][EtaPrimeBytes]byte

	// ------------------------ CONSISTENCY CHECK --------------------------- //
	// Challenge (χ_i) ∈ [M]×[σ]bits is the random challenge for the consistency check.
	Challenge [M][SigmaBytes]byte

	// ChallengeResponse (x_val, t_val) is the consistency check from the receiver,
	// to be verified by the Sender.
	ChallengeResponse struct {
		x_val [SigmaBytes]byte        // plain x in the protocol
		t_val [Kappa][SigmaBytes]byte // plain t^i in the protocol
	}

	// --------------------------- (Random) OTe ----------------------------- //
	// OTeSenderOutput (v_0, v_1) ∈ [2][η][κ]bits is the output of the sender in
	// the OTe protocol ("InputOpt1" & "InputOpt2" in the diagram above)
	OTeSenderOutput [2][Eta][KappaBytes]byte

	// OTeReceiverOutput (v_x) ∈ [η][κ]bits is the output of the receiver in the
	// OTe protocol ("DeltaOpt" in the diagram above)
	OTeReceiverOutput [Eta][KappaBytes]byte

	// ------------------------- (Correlated) COTe -------------------------- //
	// COTeInputOpt (α) ∈ [η]curve.Scalar is the input of the sender in the COTe protocol
	COTeInputOpt [Eta]curves.Scalar

	// DerandomizeMask (τ) ∈ [η]curve.Scalar is the correlation mask
	DerandomizeMask [Eta]curves.Scalar

	// COTeSenderOutput (z_A) ∈ [η]curve.Scalar is the output of the sender in
	// the COTe protocol, ("Correlation" in the diagram above)
	COTeSenderOutput [Eta]curves.Scalar

	// COTeReceiverOutput (z_B) is the output of the receiver in the COTe protocol (DeltaOpt)
	COTeReceiverOutput [Eta]curves.Scalar // z_B ∈ [η]curve.Scalar are correlated group elements.

)

// -------------------------------------------------------------------------- //
// -------------------------------- ROUNDS ---------------------------------- //
// -------------------------------------------------------------------------- //
// Round1Output is the receiver's PUBLIC output of round1 of OTe/COTe, to be sent to the Sender.
type Round1Output struct {
	// expansionMask (u_i) ∈ [κ][η']bits is the expanded and masked PRG outputs
	expansionMask ExpansionMask
	// challengeResponseFiatShamir is the challenge response for the consistency,
	// containing x_val ∈ [σ]bits, t_val ∈ [κ][σ]bits
	challengeResponseFiatShamir ChallengeResponse
}

// Round1Extend uses the PRG to extend the baseOT seeds, then proves consistency of the extension.
func (receiver *Receiver) Round1ExtendAndProveConsistency(
	oTeInputChoices *OTeInputChoices, // x_i ∈ [η]bits
) (extPackedChoices *ExtPackedChoices, // x_i ∈ [η']bits
	oTeReceiverOutput *OTeReceiverOutput, // v_x ∈ [η][κ]bits
	round1Output *Round1Output, // u_i ∈ [κ][η']bits, x_val ∈ [σ]bits, t_val ∈ [κ][σ]bits
	err error) {
	round1Output = &Round1Output{}

	// (Ext.1) Store the input choices and fill the rest with random values
	extPackedChoices = &ExtPackedChoices{}
	copy(extPackedChoices[:EtaBytes], (*oTeInputChoices)[:])
	if _, err = rand.Read(extPackedChoices[EtaBytes:]); err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "sampling random bits for Softspoken OTe (Ext.1)")
	}
	// (Ext.2) Expand the baseOT results using them as seed to the PRG
	extOptions := &ExtOptions{}
	for i := 0; i < Kappa; i++ {
		for k := 0; k < KeyCount; k++ {
			// k^i_{Δ_i} --(PRG)--> t^i_{Δ_i}
			err = PRG(receiver.uniqueSessionId[:],
				receiver.baseOtSeeds.OneTimePadEncryptionKeys[i][k][:],
				extOptions[k][i][:])
			if err != nil {
				return nil, nil, nil, errs.WrapFailed(err, "bad PRG for SoftSpoken OTe (Ext.2)")
			}
		}
	}
	// (Ext.3) Compute u_i and send it
	for i := 0; i < Kappa; i++ {
		for j := 0; j < EtaPrimeBytes; j++ {
			round1Output.expansionMask[i][j] = extOptions[0][i][j] ^ extOptions[1][i][j] ^ extPackedChoices[j]
		}
	}

	// (Check.1) Generate the challenge (χ) using Fiat-Shamir heuristic
	challengeFiatShamir := &Challenge{}
	for i := 0; i < M; i++ {
		copy(challengeFiatShamir[i][:], receiver.transcript.ExtractBytes([]byte("OTe challenge"), SigmaBytes))
	}
	// (Check.2) Compute x_val and t_val
	receiver.ComputeChallengeResponse(extPackedChoices, extOptions, challengeFiatShamir, &round1Output.challengeResponseFiatShamir)

	// (T&R.1) Transpose t^i_0 into t_j
	t_j := transposeBooleanMatrix(extOptions[0]) // t_j ∈ [η'][κ]bits
	// (T&R.2) Hash η rows of t_j using the index as salt.
	oTeReceiverOutput = &OTeReceiverOutput{}
	err = HashSalted(&receiver.uniqueSessionId, t_j[:], oTeReceiverOutput[:])
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "bad hashing t_j for SoftSpoken COTe (T&R.2)")
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
	InputOpts []COTeInputOpt, // Input opts (α_i) ∈ [η]curve.Scalar
) (oTeSenderOutput *OTeSenderOutput, cOTeSenderOutputs []COTeSenderOutput, round2Output *Round2Output, err error) {
	// (Ext.2) Expand the baseOT results using them as seed to the PRG
	extChosenOpt := ExtDeltaOpt{}
	for i := 0; i < Kappa; i++ {
		// This is the core expansion of the OT: k^i_{Δ_i} --(PRG)--> t^i_{Δ_i}
		PRG(sender.uniqueSessionId[:],
			sender.baseOtSeeds.OneTimePadDecryptionKey[i][:],
			extChosenOpt[i][:])
	}

	// (Ext.4) Compute q_i = Δ_i • u_i + t_i (constant time)
	extCorrelations := ExtCorrelations{}
	for i := 0; i < Kappa; i++ {
		for j := 0; j < EtaPrimeBytes; j++ {
			qiTemp := round1Output.expansionMask[i][j] ^ extChosenOpt[i][j]
			if sender.baseOtSeeds.RandomChoiceBits[i] != 0 {
				extCorrelations[i][j] = qiTemp
			} else {
				extCorrelations[i][j] = extChosenOpt[i][j]
			}
		}
	}

	// (T&R.1, T&R.3) Transpose and Randomize the correlations (q^i -> v_0 and q^i+Δ -> v_1)
	// (T&R.1) Transpose q^i -> q_j and q^i+Δ -> q_j+Δ
	extCorrelationsTransposed := transposeBooleanMatrix(extCorrelations)
	var extCorrelationsTransposedPlusDelta [Eta][KappaBytes]byte
	copy(extCorrelationsTransposedPlusDelta[:], extCorrelationsTransposed[:Eta])
	for i := 0; i < KappaBytes; i++ {
		Delta := sender.baseOtSeeds.PackedRandomChoiceBits[i]
		for j := 0; j < Eta; j++ {
			extCorrelationsTransposedPlusDelta[j][i] ^= Delta
		}
	}
	// (T&R.3) Randomize by hashing the first η rows of q_j and q_j+Δ (throwing away the rest)
	oTeSenderOutput = &OTeSenderOutput{}
	err = HashSalted(&sender.uniqueSessionId, extCorrelationsTransposed[:], oTeSenderOutput[0][:])
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "bad hashing q_j for SoftSpoken COTe (T&R.3)")
	}
	err = HashSalted(&sender.uniqueSessionId, extCorrelationsTransposedPlusDelta[:], oTeSenderOutput[1][:])
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "bad hashing q_j_pDelta for SoftSpoken COTe (T&R.3)")
	}

	// (Check.1) Generate the challenge (χ) using Fiat-Shamir heuristic
	challengeFiatShamir := Challenge{}
	for i := 0; i < M; i++ {
		copy(challengeFiatShamir[i][:], sender.transcript.ExtractBytes([]byte("OTe challenge"), SigmaBytes))
	}
	// (Check.3) Check the consistency of the challenge response computing q^i
	err = sender.CheckConsistency(&challengeFiatShamir, &round1Output.challengeResponseFiatShamir, &extCorrelations)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "bad consistency check for SoftSpoken COTe (Check.3)")
	}

	// Return OTe and avoid derandomizing if the input opts are not provided
	if InputOpts == nil {
		return oTeSenderOutput, nil, nil, nil
	}

	// (Derand.1) Compute the derandomization mask τ and the correlation z_A
	round2Output = &Round2Output{}
	if !sender.useForcedReuse && len(InputOpts) != 1 {
		return nil, nil, nil, errs.NewInvalidArgument("InputOpts length != 1. Set useForcedReuse, or set a higher value of L, or loop over the InputOpts")
	}
	if sender.useForcedReuse {
		cOTeSenderOutputs, round2Output.derandomizeMasks, err =
			sender.ComputeDerandomizeMaskForcedReuse(oTeSenderOutput, InputOpts)
		if err != nil {
			return nil, nil, nil, errs.WrapFailed(err, "bad forced-reuse derandomization for SoftSpoken COTe (Derand.1)")
		}
	} else {
		cOTeSenderOutputs = make([]COTeSenderOutput, 1)
		round2Output.derandomizeMasks = make([]DerandomizeMask, 1)
		err = sender.ComputeDerandomizeMask(oTeSenderOutput, &InputOpts[0], &cOTeSenderOutputs[0], &round2Output.derandomizeMasks[0])
		if err != nil {
			return nil, nil, nil, errs.WrapFailed(err, "bad derandomization for SoftSpoken COTe (Derand.1)")
		}
	}
	return oTeSenderOutput, cOTeSenderOutputs, round2Output, nil
}

// Round3Derandomize answers to the challenge of S.
func (receiver *Receiver) Round3Derandomize(
	round2Output *Round2Output,
	extPackedChoices *ExtPackedChoices,
	oTeReceiverOutput *OTeReceiverOutput,
) (cOTeReceiverOutput []COTeReceiverOutput, err error) {

	// (Derand.2) Apply derandomize Mask to
	if !receiver.useForcedReuse && len(round2Output.derandomizeMasks) != 1 {
		return nil, errs.NewInvalidArgument("derandomizeMasks length must be 1 unless forced reuse is set. Alternatively, set a higher value of L or loop over the derandomizeMasks")
	}
	if receiver.useForcedReuse {
		cOTeReceiverOutput, err = receiver.DerandomizeForcedReuse(oTeReceiverOutput, extPackedChoices, round2Output.derandomizeMasks)
		if err != nil {
			return nil, errs.WrapFailed(err, "bad forced-reuse derandomization for SoftSpoken COTe (Derand.2)")
		}
	} else {
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
// (Check.2) Compute the challenge response x, t^i \forall i \in [kappa]
func (receiver *Receiver) ComputeChallengeResponse(extPackedChoices *ExtPackedChoices, extOptions *ExtOptions, challenge *Challenge, challengeResponse *ChallengeResponse) {
	// 		x = x^hat_{m+1} ...
	copy(challengeResponse.x_val[:], extPackedChoices[EtaBytes:EtaBytes+SigmaBytes])
	// 		                ... + Σ{j=0}^{m-1} χ_j • x_hat_j
	for j := 0; j < M; j++ {
		x_hat_j := extPackedChoices[j*SigmaBytes : (j+1)*SigmaBytes]
		Chi_j := challenge[j][:]
		for k := 0; k < SigmaBytes; k++ {
			challengeResponse.x_val[k] ^= (Chi_j[k] & x_hat_j[k])
		}
	}
	// 		t^i = ...
	for i := 0; i < Kappa; i++ {
		//         ... t^i_hat_{m+1} ...
		copy(challengeResponse.t_val[i][:], extOptions[0][i][EtaBytes:EtaBytes+SigmaBytes])
		//                           ... + Σ{j=0}^{m-1} χ_j • t^i_hat_j
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
		// q^i = q^i_hat_{m+1} ...
		copy(qi_val[:], extCorrelations[i][EtaBytes:EtaBytes+SigmaBytes])
		//                     ... + Σ{j=0}^{m-1} χ_j • q^i_hat_j
		for j := 0; j < M; j++ {
			qi_hat_j := extCorrelations[i][j*SigmaBytes : (j+1)*SigmaBytes]
			Chi_j := challenge[j][:]
			for k := 0; k < SigmaBytes; k++ {
				qi_val[k] ^= (qi_hat_j[k] & Chi_j[k])
			}
		}
		//  and ABORT if q^i != t^i + Δ_i • x   ∀ i ∈[κ]
		for k := 0; k < SigmaBytes; k++ {
			qi_sum = challengeResponse.t_val[i][k] ^ challengeResponse.x_val[k]
			if sender.baseOtSeeds.RandomChoiceBits[i] != 0 {
				q_expected = qi_sum
			} else {
				q_expected = challengeResponse.t_val[i][k]
			}
			if !(q_expected == qi_val[k]) {
				return errs.NewIdentifiableAbort("q_val != q_expected in SoftspokenOT")
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
	for j := 0; j < Eta; j++ {
		// z_A_j = ECP(v_0_j)
		cOTeSenderOutput[j], err = sender.curve.Scalar.SetBytes(oTeSenderOutput[0][j][:])
		if err != nil {
			return errs.WrapFailed(err, "bad v_0 mapping to curve elements (Derand.1)")
		}
		// τ_j = ECP(v_1_j) - z_A_j + α_j
		derandomizeMask[j], err = sender.curve.Scalar.SetBytes(oTeSenderOutput[1][j][:])
		if err != nil {
			return errs.WrapFailed(err, "bad v_1 mapping to curve elements (Derand.1)")
		}
		derandomizeMask[j] = derandomizeMask[j].Sub(cOTeSenderOutput[j]).Add(InputOpts[j])
	}
	return nil
}

// (Derand.1[Forced-Reuse]) Derandomize (z_A) by mapping to curve points, establishing
// the correlation and creating the derandomization mask. The force-reuse version
// applies the same OTe output batch to all the input opts.
func (sender *Sender) ComputeDerandomizeMaskForcedReuse(oTeSenderOutput *OTeSenderOutput, inputOpts []COTeInputOpt) (cOTeSenderOutputs []COTeSenderOutput, derandomizeMasks []DerandomizeMask, err error) {
	inputBatchLen := len(inputOpts)
	cOTeSenderOutputs = make([]COTeSenderOutput, inputBatchLen)
	derandomizeMasks = make([]DerandomizeMask, inputBatchLen)
	for k := 0; k > inputBatchLen; k++ {
		// Apply the same OTe batch to all the inputs
		err = sender.ComputeDerandomizeMask(oTeSenderOutput, &inputOpts[k], &cOTeSenderOutputs[k], &derandomizeMasks[k])
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "bad Sender Forced Reuse derandomization (Derand.1)")
		}
	}
	return cOTeSenderOutputs, derandomizeMasks, nil
}

// (Derand.2) Derandomize using the mask (τ) to obtain the COTe receiver output (z_B).
// (constant time)
func (receiver *Receiver) Derandomize(
	oTeReceiverOutput *OTeReceiverOutput,
	derandomizeMask *DerandomizeMask,
	extPackChoices *ExtPackedChoices,
	cOTeReceiverOutput *COTeReceiverOutput,
) (err error) {
	var v_x_NegCurve, v_x_curve_corr curves.Scalar
	for j := 0; j < Eta; j++ {
		// ECP(v_x_j)
		v_x_NegCurve, err = receiver.curve.Scalar.SetBytes(oTeReceiverOutput[j][:])
		if err != nil {
			return errs.WrapFailed(err, "bad v_x mapping to curve elements (Derand.1)")
		}
		v_x_NegCurve = v_x_NegCurve.Neg()
		v_x_curve_corr = derandomizeMask[j].Add(v_x_NegCurve)
		if UnpackBit(j, extPackChoices[:]) != 0 {
			// z_B_j = τ_j - ECP(v_x_j)  if x_j == 1
			cOTeReceiverOutput[j] = v_x_curve_corr
		} else {
			//       =     - ECP(v_x_j)  if x_j == 0
			cOTeReceiverOutput[j] = v_x_NegCurve
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
	for k := 0; k > inputBatchLen; k++ {
		// Apply the same OTe batch to all the masks
		err = receiver.Derandomize(oTeReceiverOutput, &derandomizeMasks[k], inputExtPackChoices, &cOTeReceiverOutput[k])
		if err != nil {
			return nil, errs.WrapFailed(err, "bad Receiver Forced-Reuse derandomization (Derand.2)")
		}
	}
	return cOTeReceiverOutput, nil
}
