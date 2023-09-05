package softspoken

import (
	crand "crypto/rand"
	"crypto/subtle"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/hashing"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
)

// Round1Output is the receiver's PUBLIC output of round1 of OTe/COTe, to be sent to the Sender.
type Round1Output struct {
	// expansionMask (u^i) ∈ [κ][η']bits is the expanded and masked PRG outputs
	expansionMask ExpansionMask
	// challengeResponse is the challenge response for the consistency,
	// containing ẋ ∈ [σ]bits, ṫ ∈ [κ][σ]bits
	challengeResponse ChallengeResponse

	_ helper_types.Incomparable
}

// Round1Extend uses the PRG to extend the baseOT seeds, then proves consistency of the extension.
func (R *Receiver) Round1ExtendAndProveConsistency(
	oTeInputChoices OTeInputChoices, // x_i ∈ [LOTe][ξ]bits
) (oTeReceiverOutput OTeReceiverOutput, // v_x ∈ [LOTe][ξ][ω][κ]bits
	round1Output *Round1Output, // u_i ∈ [κ][η']bits, ẋ ∈ [σ]bits, ṫ ∈ [κ][σ]bits
	err error,
) {
	round1Output = &Round1Output{}

	// Sanitise inputs and compute sizes
	LOTe := len(oTeInputChoices) // Number of ξ×ω×κ-bit output OTe batches
	if LOTe == 0 {
		return nil, nil, errs.NewInvalidArgument("nil (oTeInputChoices) in input arguments of Round1ExtendAndProveConsistency")
	}
	if (LOTe > 1) && (R.useForcedReuse) {
		return nil, nil, errs.NewInvalidArgument("len(choices) should be 1 when useForcedReuse is set (is %d)", LOTe)
	}
	eta := LOTe * Xi                       // η = L*ξ
	etaBytes := eta >> 3                   // η/8
	etaPrimeBytes := etaBytes + SigmaBytes // η'=η+σ (η'=ξ+σ if useForcedReuse is set)

	// (Ext.1) Store the input choices and fill the rest with random values
	R.extPackedChoices = make([]byte, etaPrimeBytes) // x_i ∈ [η']bits
	for l := 0; l < LOTe; l++ {
		copy(R.extPackedChoices[l*XiBytes:(l+1)*XiBytes], oTeInputChoices[l][:])
	}
	if _, err = crand.Read(R.extPackedChoices[etaBytes:]); err != nil {
		return nil, nil, errs.WrapRandomSampleFailed(err, "sampling random bits for Softspoken OTe (Ext.1)")
	}
	// (Ext.2) Expand the baseOT results using them as seed to the PRG
	extOptions := &ExtOptions{}
	for i := 0; i < Kappa; i++ {
		// k^i_0 --(PRG)--> t^i_0
		extOptions[0][i], err = hashing.PRG(R.sid, R.baseOtSeeds.OneTimePadEncryptionKeys[i][0][:], etaPrimeBytes)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "bad PRG for SoftSpoken OTe (Ext.2)")
		}
		// k^i_1 --(PRG)--> t^i_1
		extOptions[1][i], err = hashing.PRG(R.sid, R.baseOtSeeds.OneTimePadEncryptionKeys[i][1][:], etaPrimeBytes)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "bad PRG for SoftSpoken OTe (Ext.2)")
		}
	}
	// (Ext.3) Compute u_i and send it
	for i := 0; i < Kappa; i++ {
		round1Output.expansionMask[i] = make([]byte, etaPrimeBytes)
		subtle.XORBytes(round1Output.expansionMask[i], extOptions[0][i], extOptions[1][i])
		subtle.XORBytes(round1Output.expansionMask[i], round1Output.expansionMask[i], R.extPackedChoices)
	}

	// (*)(Fiat-Shamir): Append the expansionMask to the transcript
	WitnessCommitment(R.transcript, &round1Output.expansionMask)

	// (Check.1) Generate the challenge (χ) using Fiat-Shamir heuristic
	M := eta / Sigma // M = η/σ
	challengeFiatShamir := GenerateChallenge(R.transcript, M)

	// (Check.2) Compute ẋ and ṫ
	R.ComputeChallengeResponse(extOptions, challengeFiatShamir, &round1Output.challengeResponse)

	// (T&R.1) Transpose t^i_0 into t_j
	t_j, err := bitstring.TransposePackedBits(extOptions[0][:]) // t_j ∈ [η'][κ]bits
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "bad transposing t^i_0 for SoftSpoken COTe")
	}
	// (T&R.2) Hash η rows of t_j using the index as salt (drop η' - η rows, used for consistency check)
	oTeReceiverOutput = make(OTeReceiverOutput, LOTe)
	err = HashSalted(R.sid, t_j[:eta], oTeReceiverOutput)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "bad hashing t_j for SoftSpoken COTe (T&R.2)")
	}

	// (*)(Fiat-Shamir): Append the challenge response to the transcript
	R.transcript.AppendMessages("OTe_challengeResponse_x_val", round1Output.challengeResponse.x_val[:])
	for i := 0; i < Kappa; i++ {
		R.transcript.AppendMessages("OTe_challengeResponse_t_val", round1Output.challengeResponse.t_val[i][:])
	}
	return oTeReceiverOutput, round1Output, nil
}

// Round2Output is the sender's PUBLIC output of round2 of OTe/COTe, to be sent to the Receiver.
type Round2Output struct {
	derandMask DerandomizeMask

	_ helper_types.Incomparable
}

// Round2Extend uses the PRG to extend the baseOT results, verifies their consistency
// and derandomizes them (COTe only).
func (S *Sender) Round2ExtendAndCheckConsistency(
	round1Output *Round1Output,
	InputOpts COTeInputOpt, // Input opts (α) ∈ [L][ξ][ω]curve.Scalar. Set to nil for OTe.
) (oTeSenderOutput *OTeSenderOutput, cOTeSenderOutput COTeSenderOutput, round2Output *Round2Output, err error) {
	// Sanitise inputs, compute sizes and allocate outputs
	if round1Output == nil {
		return nil, nil, nil, errs.NewInvalidArgument("nil (round1Output) in input arguments of Round2 of COTe")
	}
	etaPrimeBytes := len(round1Output.expansionMask[0])
	etaPrime := etaPrimeBytes << 3 // η' = LOTe*ξ + σ
	eta := etaPrime - Sigma        // η = LOTe*ξ
	LOTe := eta / Xi               // LOTe = (η' - σ)/ξ (L = 1 if useForcedReuse is set)
	L := len(InputOpts)            // Number of ξ×ω-scalar batches (L = LOTe unless useForcedReuse is set)
	if S.useForcedReuse {          // Forced reuse: reuse a single ξ×ω×κ-bit OTe batch
		if LOTe != 1 {
			return nil, nil, nil, errs.NewInvalidArgument("ExpansionMask batch length (L=%d) should be 1 (Forced Reuse)", LOTe)
		}
	} else { // No forced reuse: get L different OTe batches
		if (L != LOTe) && (L != 0) { // L = 0 if InputOpts is nil (to just run OTe)
			return nil, nil, nil, errs.NewInvalidArgument("InputOpts and expansionMask lengths don't match (%d != %d) ", LOTe, L)
		}
	}
	oTeSenderOutput = &OTeSenderOutput{
		make([][Xi][ROTeWidth][KappaBytes]byte, LOTe), make([][Xi][ROTeWidth][KappaBytes]byte, LOTe),
	}

	// (Ext.2) Expand the baseOT results using them as seed to the PRG
	extDeltaOpt := ExtDeltaOpt{}
	for i := 0; i < Kappa; i++ {
		// This is the core expansion of the OT: k^i_{Δ_i} --(PRG)--> t^i_{Δ_i}
		extDeltaOpt[i], err = hashing.PRG(S.sid, S.baseOtSeeds.OneTimePadDecryptionKey[i][:], etaPrimeBytes)
		if err != nil {
			return nil, nil, nil, errs.WrapFailed(err, "bad PRG for SoftSpoken COTe (Ext.2)")
		}
	}
	// (Ext.4) Compute q_i = Δ_i • u_i + t_i (constant time)
	extCorrelations := ExtCorrelations{}
	qiTemp := make([]byte, etaPrimeBytes)
	for i := 0; i < Kappa; i++ {
		extCorrelations[i] = extDeltaOpt[i]
		subtle.XORBytes(qiTemp, round1Output.expansionMask[i], extDeltaOpt[i])
		subtle.ConstantTimeCopy(S.baseOtSeeds.RandomChoiceBits[i], extCorrelations[i], qiTemp)
	}

	// (T&R.1, T&R.3) Transpose and Randomise the correlations (q^i -> v_0 and q^i+Δ -> v_1)
	// (T&R.1) Transpose q^i -> q_j and add Δ -> q_j+Δ
	qjTransposed, err := bitstring.TransposePackedBits(extCorrelations[:]) // q_j ∈ [η'][κ]bits
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "bad transposing q^i for SoftSpoken COTe")
	}
	qjTransposedPlusDelta := make([][]byte, eta) // q_j+Δ ∈ [η][κ]bits
	for j := 0; j < eta; j++ {
		qjTransposedPlusDelta[j] = make([]byte, KappaBytes)
	}
	for j := 0; j < eta; j++ { // drop η' - η rows, used for consistency check
		subtle.XORBytes(qjTransposedPlusDelta[j], qjTransposed[j], S.baseOtSeeds.PackedRandomChoiceBits)
	}
	// (T&R.3) Randomise by hashing the first η rows of q_j and q_j+Δ (drop η' - η = σ rows)
	err = HashSalted(S.sid, qjTransposed[:eta], oTeSenderOutput[0])
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "bad hashing q_j for SoftSpoken COTe (T&R.3)")
	}
	err = HashSalted(S.sid, qjTransposedPlusDelta[:eta], oTeSenderOutput[1])
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "bad hashing q_j_pDelta for SoftSpoken COTe (T&R.3)")
	}

	// (*)(Fiat-Shamir): Append the expansionMask to the transcript
	WitnessCommitment(S.transcript, &round1Output.expansionMask)

	// (Check.1) Generate the challenge (χ) using Fiat-Shamir heuristic
	M := eta / Sigma // M = η/σ
	challengeFiatShamir := GenerateChallenge(S.transcript, M)

	// (Check.3) Check the consistency of the challenge response computing q^i
	err = S.VerifyChallengeResponse(challengeFiatShamir, &round1Output.challengeResponse, &extCorrelations)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "bad consistency check for SoftSpoken COTe (Check.3)")
	}

	// (*)(Fiat-Shamir): Append the challenge response to the transcript
	S.transcript.AppendMessages("OTe_challengeResponse_x_val", round1Output.challengeResponse.x_val[:])
	for i := 0; i < Kappa; i++ {
		S.transcript.AppendMessages("OTe_challengeResponse_t_val", round1Output.challengeResponse.t_val[i][:])
	}

	// Return OTe and avoid derandomizing if the input opts are not provided
	if InputOpts == nil {
		return oTeSenderOutput, nil, nil, nil
	}

	// (Derand.1) Compute the derandomization mask τ and the output correlation z_A
	cOTeSenderOutput = make(COTeSenderOutput, L)
	round2Output = &Round2Output{derandMask: make(DerandomizeMask, L)}
	var idxOTe int
	for l := 0; l < L; l++ {
		for i := 0; i < Xi; i++ {
			for j := 0; j < ROTeWidth; j++ {
				// if forced reuse, use always the first OTe batch (idxOTe = 0)
				if S.useForcedReuse {
					idxOTe = 0
				} else {
					idxOTe = l
				}
				// z_A_j = ECP(v_0_j)
				cOTeSenderOutput[l][i][j], err = S.curve.Scalar().SetBytes(
					oTeSenderOutput[0][idxOTe][i][j][:])
				if err != nil {
					return nil, nil, nil, errs.WrapFailed(err, "bad v_0 mapping to curve elements (Derand.1)")
				}
				// τ_j = ECP(v_1_j) - z_A_j + α_j
				round2Output.derandMask[l][i][j], err = S.curve.Scalar().SetBytes(
					oTeSenderOutput[1][idxOTe][i][j][:])
				if err != nil {
					return nil, nil, nil, errs.WrapFailed(err, "bad v_1 mapping to curve elements (Derand.1)")
				}
				round2Output.derandMask[l][i][j] = round2Output.derandMask[l][i][j].
					Sub(cOTeSenderOutput[l][i][j]).Add(InputOpts[l][i][j])
			}
		}
	}

	// (*)(Fiat-Shamir): Append the derandomization mask to the transcript
	for l := 0; l < L; l++ {
		for i := 0; i < Xi; i++ {
			for j := 0; j < ROTeWidth; j++ {
				S.transcript.AppendMessages("OTe_derandomizeMask",
					round2Output.derandMask[l][i][j].Bytes())
			}
		}
	}

	return oTeSenderOutput, cOTeSenderOutput, round2Output, nil
}

// Round3Derandomize uses the derandomization mask to derandomize the COTe output.
func (R *Receiver) Round3Derandomize(
	round2Output *Round2Output,
	oTeReceiverOutput OTeReceiverOutput,
) (cOTeReceiverOutput COTeReceiverOutput, err error) {
	// Sanitise input, compute sizes and allocate outputs
	if (round2Output == nil) || (len(oTeReceiverOutput) == 0) {
		return nil, errs.NewInvalidArgument("nil in input arguments of Round3Derandomize")
	}
	LOTe := len(oTeReceiverOutput)         // Number of ξ×ω×κ-bit OTe batches
	L := len(round2Output.derandMask)      // Number of ξ×ω-scalar COTe batches
	if (R.useForcedReuse) && (LOTe != 1) { // Forced reuse: reuse a single OTe batch
		return nil, errs.NewInvalidArgument("oTeReceiverOutput batch length (L=%d) should be 1 (Forced Reuse)", LOTe)
	} else if (!R.useForcedReuse) && (L != LOTe) { // No forced reuse: get L different OTe batches
		return nil, errs.NewInvalidArgument("oTeReceiverOutput and derandMask lengths don't match (%d != %d) ", LOTe, L)
	}
	cOTeReceiverOutput = make(COTeReceiverOutput, L)

	// (*)(Fiat-Shamir): Append the derandomization mask to the transcript
	for l := 0; l < L; l++ {
		for i := 0; i < Xi; i++ {
			for j := 0; j < ROTeWidth; j++ {
				R.transcript.AppendMessages("OTe_derandomizeMask",
					round2Output.derandMask[l][i][j].Bytes())
			}
		}
	}

	// (Derand.2) Apply derandomization Mask to the ROTe output
	var v_x_NegCurve, v_x_curve_corr curves.Scalar
	var idxOTe int
	for l := 0; l < L; l++ {
		for i := 0; i < Xi; i++ {
			for j := 0; j < ROTeWidth; j++ {
				// if forced reuse, use always the first OTe batch (idxOTe = 0)
				if R.useForcedReuse {
					idxOTe = 0
				} else {
					idxOTe = l
				}
				// ECP(v_x_j)
				v_x_NegCurve, err = R.curve.Scalar().SetBytes(oTeReceiverOutput[idxOTe][i][j][:])
				if err != nil {
					return nil, errs.WrapFailed(err, "bad v_x mapping to curve elements (Derand.2)")
				}
				v_x_NegCurve = v_x_NegCurve.Neg()
				v_x_curve_corr = round2Output.derandMask[l][i][j].Add(v_x_NegCurve)
				bit, err := bitstring.SelectBit(R.extPackedChoices[:], idxOTe*Xi+i)
				if err != nil {
					return nil, errs.WrapFailed(err, "cannot select bit")
				}
				if bit != 0 {
					// z_B_j = τ_j - ECP(v_x_j)  if x_j == 1
					cOTeReceiverOutput[l][i][j] = v_x_curve_corr
				} else {
					//       =     - ECP(v_x_j)  if x_j == 0
					cOTeReceiverOutput[l][i][j] = v_x_NegCurve
				}
			}
		}
	}
	if err != nil {
		return nil, errs.WrapFailed(err, "bad derandomization for SoftSpoken COTe (Derand.2)")
	}
	return cOTeReceiverOutput, nil
}

// -------------------------------------------------------------------------- //
// ---------------- SIGMA-LIKE PROTOCOL FOR CONSISTENCY CHECK --------------- //
// -------------------------------------------------------------------------- //
// This section contains the functions for the Sigma-like protocol, used to
// prove consistency of the extension, with four algorithms:
// 1. WitnessCommitment: the receiver commits (u_i) to the witness (x_i) and
//    "sends" the commitment to the sender.
// 2. ComputeChallenge: the sender computes the challenge (χ).
// 3. ComputeChallengeResponse: the receiver computes the challenge response (ẋ, ṫ^i)
//    using the challenge (χ).
// 4. VerifyChallengeResponse: the sender verifies the challenge response (ẋ, ṫ^i)
//    using the challenge (χ) and the commitment (u_i).
//
// We employ the Fiat-Shamir heuristic, appending u_i to the transcript and
// generating the challenge (χ) from the transcript.

// WitnessCommitment (*)(Fiat-Shamir) Appends the expansionMask to the transcript.
func WitnessCommitment(t transcripts.Transcript, expansionMask *ExpansionMask) {
	for i := 0; i < Kappa; i++ {
		t.AppendMessages("OTe_expansionMask", expansionMask[i])
	}
}

// GenerateChallenge (*)(Fiat-Shamir) Generates the challenge (χ) using Fiat-Shamir heuristic.
func GenerateChallenge(t transcripts.Transcript, M int) (challenge Challenge) {
	challengeFiatShamir := make(Challenge, M)
	for i := 0; i < M; i++ {
		bytes, _ := t.ExtractBytes("OTe_challenge_Chi", SigmaBytes)
		copy(challengeFiatShamir[i][:], bytes)
	}
	return challengeFiatShamir
}

// ComputeChallengeResponse (Check.2) Computes the challenge response ẋ, ṫ^i ∀i∈[κ].
func (R *Receiver) ComputeChallengeResponse(extOptions *ExtOptions, challenge Challenge, challengeResponse *ChallengeResponse) {
	M := len(challenge)         // M = η/σ
	etaBytes := (M * Sigma) / 8 // η = M*σ
	// 		ẋ = x̂_{m+1} ...
	copy(challengeResponse.x_val[:], R.extPackedChoices[etaBytes:etaBytes+SigmaBytes])
	// 		                ... + Σ{j=1}^{m} χ_j • x̂_j
	for j := 0; j < M; j++ {
		x_hat_j := R.extPackedChoices[j*SigmaBytes : (j+1)*SigmaBytes]
		Chi_j := challenge[j][:]
		for k := 0; k < SigmaBytes; k++ {
			challengeResponse.x_val[k] ^= (Chi_j[k] & x_hat_j[k])
		}
	}
	// 		ṫ^i = ...
	for i := 0; i < Kappa; i++ {
		//         ... t^i_hat_{m+1} ...
		copy(challengeResponse.t_val[i][:], extOptions[0][i][etaBytes:etaBytes+SigmaBytes])
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

// VerifyChallengeResponse (Check.3) checks the consistency of the extension.
func (S *Sender) VerifyChallengeResponse(
	challenge Challenge,
	challengeResponse *ChallengeResponse,
	extCorrelations *ExtCorrelations,
) error {
	// Compute sizes
	M := len(challenge)                                // M = η/σ
	etaBytes := (len(extCorrelations[0])) - SigmaBytes // η =  η' - σ
	var qi_val, qi_expected [SigmaBytes]byte
	for i := 0; i < Kappa; i++ {
		// q̇^i = q^i_hat_{m+1} ...
		copy(qi_val[:], extCorrelations[i][etaBytes:etaBytes+SigmaBytes])
		//                     ... + Σ{j=1}^{m} χ_j • q^i_hat_j
		for j := 0; j < M; j++ {
			qi_hat_j := extCorrelations[i][j*SigmaBytes : (j+1)*SigmaBytes]
			Chi_j := challenge[j][:]
			for k := 0; k < SigmaBytes; k++ {
				qi_val[k] ^= (qi_hat_j[k] & Chi_j[k])
			}
		}
		// ABORT if q̇^i != ṫ^i + Δ_i • ẋ  ∀ i ∈[κ]
		subtle.XORBytes(qi_expected[:], challengeResponse.t_val[i][:], challengeResponse.x_val[:])
		subtle.ConstantTimeCopy((1 - S.baseOtSeeds.RandomChoiceBits[i]), qi_expected[:], challengeResponse.t_val[i][:])
		if subtle.ConstantTimeCompare(qi_expected[:], qi_val[:]) == 0 {
			return errs.NewIdentifiableAbort("receiver", "q_val != q_expected in SoftspokenOT. OTe consistency check failed")
		}
	}
	return nil
}
