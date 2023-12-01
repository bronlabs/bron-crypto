package softspoken

import (
	"crypto/subtle"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

type Round1Output struct {
	ExpansionMask     ExtMessage
	Witness           Witness
	ChallengeResponse ChallengeResponse

	_ types.Incomparable
}

// Round1 uses the PRG to extend the baseOT seeds, then proves consistency of the extension.
func (R *Receiver) Round1(oTeInputChoices OTeInputChoices) (oTeReceiverOutput OTeMessage, r1Out *Round1Output, err error) {
	r1Out = &Round1Output{}

	// Sanitise inputs and compute sizes
	LOTe := len(oTeInputChoices) // Number of ξ×κ-bit output OTe batches
	if LOTe == 0 {
		return nil, nil, errs.NewInvalidArgument("nil (oTeInputChoices) in input arguments of Round1ExtendAndProveConsistency")
	}
	if (LOTe > 1) && (R.useForcedReuse) {
		return nil, nil, errs.NewInvalidArgument("len(choices) should be 1 when useForcedReuse is set (is %d)", LOTe)
	}
	eta := LOTe * Xi                       // η = LOTe*ξ (η = ξ if useForcedReuse, as in DKLs23)
	etaBytes := eta >> 3                   // η/8
	etaPrimeBytes := etaBytes + SigmaBytes // η'=η+σ (η'=ξ+σ if useForcedReuse, as in DKLs23)

	// EXTENSION
	// step 1.1.1 (Ext.1)
	R.extPackedChoices = make([]byte, etaPrimeBytes) // x' ∈ [η']bits
	for l := 0; l < LOTe; l++ {
		copy(R.extPackedChoices[l*XiBytes:(l+1)*XiBytes], oTeInputChoices[l][:])
	}
	if _, err = R.csrand.Read(R.extPackedChoices[etaBytes:]); err != nil {
		return nil, nil, errs.WrapRandomSampleFailed(err, "sampling random bits for Softspoken OTe (Ext.1)")
	}
	// step 1.1.2 (Ext.2)
	extOptions := &[2]ExtMessage{}
	for i := 0; i < Kappa; i++ {
		extOptions[0][i] = make([]byte, etaPrimeBytes) // k^i_0 --(PRG)--> t^i_0
		extOptions[1][i] = make([]byte, etaPrimeBytes) // k^i_1 --(PRG)--> t^i_1
		err = R.prg.Seed(R.baseOtSeeds.OneTimePadEncryptionKeys[i][0][:], R.sid)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "bad PRG seeding for SoftSpoken OTe (Ext.2)")
		}
		if _, err = R.prg.Read(extOptions[0][i]); err != nil {
			return nil, nil, errs.WrapFailed(err, "bad PRG reading for SoftSpoken OTe (Ext.2)")
		}
		err = R.prg.Seed(R.baseOtSeeds.OneTimePadEncryptionKeys[i][1][:], R.sid)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "bad PRG for SoftSpoken OTe (Ext.2)")
		}
		if _, err = R.prg.Read(extOptions[1][i]); err != nil {
			return nil, nil, errs.WrapFailed(err, "bad PRG for SoftSpoken OTe (Ext.2)")
		}
	}
	// step 1.1.3 (Ext.3)
	for i := 0; i < Kappa; i++ {
		r1Out.ExpansionMask[i] = make([]byte, etaPrimeBytes) // u_i = t^i_0 + t^i_1 + Δ_i
		subtle.XORBytes(r1Out.ExpansionMask[i], extOptions[0][i], extOptions[1][i])
		subtle.XORBytes(r1Out.ExpansionMask[i], r1Out.ExpansionMask[i], R.extPackedChoices)
	}

	// CONSISTENCY CHECK
	// step 1.2.1.[1-2] (*)(Check.1, Fiat-Shamir)
	r1Out.Witness, err = commitWitness(R.transcript, &r1Out.ExpansionMask, nil, R.csrand)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "bad commitment for SoftSpoken COTe (Check.1)")
	}
	// step 1.2.1.3 (*)(Check.1, Fiat-Shamir)
	M := eta / Sigma                                          // M = η/σ
	challengeFiatShamir := generateChallenge(R.transcript, M) // χ
	// step 1.2.2 (Check.2) Compute ẋ and ṫ
	R.computeResponse(extOptions, challengeFiatShamir, &r1Out.ChallengeResponse)

	// (*)(Fiat-Shamir): Append the challenge response to the transcript (to be used by protocols sharing the transcript)
	R.transcript.AppendMessages("OTe_challengeResponse_x_val", r1Out.ChallengeResponse.X_val[:])
	for i := 0; i < Kappa; i++ {
		R.transcript.AppendMessages("OTe_challengeResponse_t_val", r1Out.ChallengeResponse.T_val[i][:])
	}

	// TRANSPOSE AND RANDOMISE
	// step 1.3.1 (T&R.1) Transpose t^i_0 into t_j
	t_j, err := bitstring.TransposePackedBits(extOptions[0][:]) // t_j ∈ [η'][κ]bits
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "bad transposing t^i_0 for SoftSpoken COTe")
	}
	// step 1.3.2 (T&R.2) Hash η rows of t_j using the sid as salt (drop η' - η rows, used for consistency check)
	R.oTeReceiverOutput = make(OTeMessage, LOTe)
	err = HashSalted(R.sid, t_j[:eta], R.oTeReceiverOutput)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "bad hashing t_j for SoftSpoken COTe (T&R.2)")
	}
	return R.oTeReceiverOutput, r1Out, nil
}

// Round2Output is the sender's output of round2 of COTe, to be sent to the Receiver.
type Round2Output struct {
	DerandMask COTeMessage

	_ types.Incomparable
}

// Round2 uses the PRG to extend the baseOT results, verifies their consistency
// and (COTe only, not in OTe) derandomizes them. Set cOTeSenderInput (α) to nil
// for OTe functionality.
func (S *Sender) Round2(round1Output *Round1Output, cOTeSenderInput COTeMessage,
) (oTeSenderOutput *[2]OTeMessage, cOTeSenderOutput COTeMessage, round2Output *Round2Output, err error) {
	// Sanitise inputs, compute sizes and allocate outputs
	if round1Output == nil {
		return nil, nil, nil, errs.NewInvalidArgument("nil (round1Output) in input arguments of Round2 of COTe")
	}
	etaPrimeBytes := len(round1Output.ExpansionMask[0])
	etaPrime := etaPrimeBytes << 3 // η' = LOTe*ξ + σ
	eta := etaPrime - Sigma        // η = LOTe*ξ
	LOTe := eta / Xi               // LOTe = (η' - σ)/ξ (L = 1 if useForcedReuse is set)
	L := len(cOTeSenderInput)      // Number of ξ×ω-scalar batches (L = LOTe unless useForcedReuse is set)
	scalarsPerSlot := 0
	if cOTeSenderInput != nil {
		scalarsPerSlot = len(cOTeSenderInput[0][0]) // ω, Number of COTe scalars per slot of OTe.
	}
	if S.useForcedReuse { // Forced reuse: reuse a single ξ×κ-bit OTe batch
		if LOTe != 1 {
			return nil, nil, nil, errs.NewInvalidArgument("ExtMessage batch length (L=%d) should be 1 (Forced Reuse)", LOTe)
		}
	} else { // No forced reuse: get L different OTe batches
		if (L != LOTe) && (L != 0) { // L = 0 if InputOpts is nil (to just run OTe)
			return nil, nil, nil, errs.NewInvalidArgument("InputOpts and expansionMask lengths don't match (%d != %d) ", LOTe, L)
		}
	}
	oTeSenderOutput = &[2]OTeMessage{
		make([][Xi][KappaBytes]byte, LOTe),
		make([][Xi][KappaBytes]byte, LOTe),
	}

	// EXTENSION
	// step 2.1.1 (Ext.1) k^i_{Δ_i} --(PRG)--> t^i_{Δ_i}
	extDeltaOpt := ExtMessage{}
	for i := 0; i < Kappa; i++ {
		extDeltaOpt[i] = make([]byte, etaPrimeBytes)
		err = S.prg.Seed(S.baseOtSeeds.OneTimePadDecryptionKey[i][:], S.sid)
		if err != nil {
			return nil, nil, nil, errs.WrapFailed(err, "bad PRG reset for SoftSpoken OTe (Ext.2)")
		}
		if _, err = S.prg.Read(extDeltaOpt[i]); err != nil {
			return nil, nil, nil, errs.WrapFailed(err, "bad PRG write for SoftSpoken OTe (Ext.2)")
		}
	}
	// step 2.1.2 (Ext.2) Compute q_i = Δ_i • u_i + t_i
	extCorrelations := ExtMessage{}
	qiTemp := make([]byte, etaPrimeBytes)
	for i := 0; i < Kappa; i++ {
		extCorrelations[i] = extDeltaOpt[i]
		subtle.XORBytes(qiTemp, round1Output.ExpansionMask[i], extDeltaOpt[i])
		subtle.ConstantTimeCopy(S.baseOtSeeds.RandomChoiceBits[i], extCorrelations[i], qiTemp)
	}

	// CONSISTENCY CHECK
	// step 2.2.1.1 (*)(Fiat-Shamir): Append the expansionMask to the transcript
	_, err = commitWitness(S.transcript, &round1Output.ExpansionMask, round1Output.Witness, S.csrand)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "bad commitment for SoftSpoken COTe (Check.1)")
	}
	// step 2.2.1.2 (Check.1.2) Generate the challenge (χ) using Fiat-Shamir heuristic
	M := eta / Sigma
	challengeFiatShamir := generateChallenge(S.transcript, M)
	// step 2.2.[2-3] (Check.3) Check the consistency of the challenge response computing q^i
	err = S.verifyChallenge(challengeFiatShamir, &round1Output.ChallengeResponse, &extCorrelations)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "bad consistency check for SoftSpoken COTe (Check.3)")
	}
	// (*)(Fiat-Shamir): Append the challenge response to the transcript
	S.transcript.AppendMessages("OTe_challengeResponse_x_val", round1Output.ChallengeResponse.X_val[:])
	for i := 0; i < Kappa; i++ {
		S.transcript.AppendMessages("OTe_challengeResponse_t_val", round1Output.ChallengeResponse.T_val[i][:])
	}

	// TRANSPOSE AND RANDOMISE
	// step 2.3.1 (T&R.1) Transpose q^i -> q_j and add Δ -> q_j+Δ
	qjTransposed, err := bitstring.TransposePackedBits(extCorrelations[:]) // q_j ∈ [η'][κ]bits
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "bad transposing q^i for SoftSpoken COTe")
	}
	qjTransposedPlusDelta := make([][]byte, eta) // q_j+Δ ∈ [η][κ]bits
	for j := 0; j < eta; j++ {
		qjTransposedPlusDelta[j] = make([]byte, KappaBytes)
		// drop last η'-η rows, they are used only for the consistency check
		subtle.XORBytes(qjTransposedPlusDelta[j], qjTransposed[j], S.baseOtSeeds.PackedRandomChoiceBits)
	}
	// step 2.3.2 (T&R.2) Randomise by hashing q_j and q_j+Δ
	err = HashSalted(S.sid, qjTransposed[:eta], oTeSenderOutput[0])
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "bad hashing q_j for SoftSpoken COTe (T&R.2)")
	}
	err = HashSalted(S.sid, qjTransposedPlusDelta[:eta], oTeSenderOutput[1])
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "bad hashing q_j_pDelta for SoftSpoken COTe (T&R.2)")
	}

	// Return OTe and avoid derandomising if the input opts are not provided
	if cOTeSenderInput == nil {
		return oTeSenderOutput, nil, nil, nil
	}

	// DERANDOMISE
	// step 2.4. (Derand)
	cOTeSenderOutput = make(COTeMessage, L)
	round2Output = &Round2Output{DerandMask: make(COTeMessage, L)}
	var idxOTe int
	for l := 0; l < L; l++ {
		// if forced reuse, use always the first OTe batch (idxOTe = 0)
		if S.useForcedReuse {
			idxOTe = 0
		} else {
			idxOTe = l
		}
		for i := 0; i < Xi; i++ {
			// step 2.4.1   z_A_j = ECS(v_0_j)
			cOTeSenderOutput[l][i], err = S.curve.HashToScalars(scalarsPerSlot, oTeSenderOutput[0][idxOTe][i][:], nil)
			if err != nil {
				return nil, nil, nil, errs.WrapHashingFailed(err, "bad hashing v_0_j for SoftSpoken COTe (Derand.1)")
			}
			// step 2.4.2   τ_j = ECS(v_1_j)...
			round2Output.DerandMask[l][i], err = S.curve.HashToScalars(scalarsPerSlot, oTeSenderOutput[1][idxOTe][i][:], nil)
			if err != nil {
				return nil, nil, nil, errs.WrapHashingFailed(err, "bad hashing v_1_j for SoftSpoken COTe (Derand.1)")
			}
			//                              ... - z_A_j + α_j
			for j := 0; j < scalarsPerSlot; j++ {
				round2Output.DerandMask[l][i][j] = round2Output.DerandMask[l][i][j].
					Sub(cOTeSenderOutput[l][i][j]).Add(cOTeSenderInput[l][i][j])
			}
		}
	}

	// (*)(Fiat-Shamir): Append the derandomization mask to the transcript
	for l := 0; l < L; l++ {
		for i := 0; i < Xi; i++ {
			for j := 0; j < scalarsPerSlot; j++ {
				S.transcript.AppendMessages("OTe_derandomizeMask",
					round2Output.DerandMask[l][i][j].Bytes())
			}
		}
	}

	return oTeSenderOutput, cOTeSenderOutput, round2Output, nil
}

// Round3 uses the derandomization mask to derandomize the COTe output.
func (R *Receiver) Round3(round2Output *Round2Output) (cOTeMessage COTeMessage, err error) {
	// Sanitise input, compute sizes and allocate outputs
	if (round2Output == nil) || (len(R.oTeReceiverOutput) == 0) {
		return nil, errs.NewInvalidArgument("nil in input arguments of Round3Derandomize")
	}
	LOTe := len(R.oTeReceiverOutput)                     // Number of ξ×κ-bit OTe batches
	L := len(round2Output.DerandMask)                    // Number of ξ×ω-scalar COTe batches
	scalarsPerSlot := len(round2Output.DerandMask[0][0]) // ω, Number of COTe scalars per slot of OTe.
	if (R.useForcedReuse) && (LOTe != 1) {               // Forced reuse: reuse a single OTe batch
		return nil, errs.NewInvalidArgument("oTeReceiverOutput batch length (L=%d) should be 1 (Forced Reuse)", LOTe)
	} else if (!R.useForcedReuse) && (L != LOTe) { // No forced reuse: get L different OTe batches
		return nil, errs.NewInvalidArgument("oTeReceiverOutput and derandMask lengths don't match (%d != %d) ", LOTe, L)
	}
	cOTeMessage = make(COTeMessage, L)

	// (*)(Fiat-Shamir): Append the derandomization mask to the transcript
	for l := 0; l < L; l++ {
		for i := 0; i < Xi; i++ {
			for j := 0; j < scalarsPerSlot; j++ {
				R.transcript.AppendMessages("OTe_derandomizeMask",
					round2Output.DerandMask[l][i][j].Bytes())
			}
		}
	}

	// step 3.1 (Derand)
	var v_x_NegCurve, v_x_curve_corr curves.Scalar
	var idxOTe int
	for l := 0; l < L; l++ {
		// if forced reuse, use always the first OTe batch (idxOTe = 0)
		if R.useForcedReuse {
			idxOTe = 0
		} else {
			idxOTe = l
		}
		for i := 0; i < Xi; i++ {
			scalars, err := R.curve.HashToScalars(scalarsPerSlot, R.oTeReceiverOutput[idxOTe][i][:], nil)
			if err != nil {
				return nil, errs.WrapHashingFailed(err, "bad hashing v_x_j for SoftSpoken COTe (Derand.2)")
			}
			cOTeMessage[l][i] = make([]curves.Scalar, scalarsPerSlot)
			for j := 0; j < scalarsPerSlot; j++ {
				// ECS(v_x_j)
				v_x_NegCurve = scalars[j].Neg()
				v_x_curve_corr = round2Output.DerandMask[l][i][j].Add(v_x_NegCurve)
				bit, err := bitstring.SelectBit(R.extPackedChoices[:], idxOTe*Xi+i)
				if err != nil {
					return nil, errs.WrapFailed(err, "cannot select bit")
				}
				if bit == 0x01 {
					// z_B_j = τ_j - ECS(v_x_j)  if x_j == 1
					cOTeMessage[l][i][j] = v_x_curve_corr
				} else {
					//       =     - ECS(v_x_j)  if x_j == 0
					cOTeMessage[l][i][j] = v_x_NegCurve
				}
			}
		}
	}
	return cOTeMessage, nil
}

// -------------------------------------------------------------------------- //
// ---------------- SIGMA-LIKE PROTOCOL FOR CONSISTENCY CHECK --------------- //
// -------------------------------------------------------------------------- //
// This section contains the functions for the Sigma-like protocol, used to
// prove consistency of the extension, with four algorithms:
// 1. commitWitness: the prover commits a statement (u_i) with the witness (r).
// 2. ComputeChallenge: the verifier computes the challenge (χ).
// 3. ComputeResponse: the prover computes the challenge response (ẋ, ṫ^i)
//    using the challenge (χ).
// 4. VerifyChallenge: the verifier verifies the challenge response (ẋ, ṫ^i)
//    using the challenge (χ) and the commitment to the statement (u_i).
//
// We employ the Fiat-Shamir heuristic, appending u_i to the transcript and
// generating the challenge (χ) from the transcript.

// commitWitness (*)(Fiat-Shamir) Appends the expansionMask to the transcript.
func commitWitness(t transcripts.Transcript, expansionMask *ExtMessage, r Witness, csrand io.Reader) (Witness, error) {
	if len(*expansionMask) == 0 {
		return nil, errs.NewIsNil("expansionMask is nil")
	}
	if r == nil {
		r = make(Witness, Kappa)
		for i := 0; i < Kappa; i++ {
			if _, err := csrand.Read(r[i][:]); err != nil {
				return nil, errs.WrapRandomSampleFailed(err, "sampling random bits for Softspoken OTe (WitnessCommitment)")
			}
		}
	}
	for i := 0; i < Kappa; i++ {
		t.AppendMessages("OTe_witnessCommitment", r[i][:])
		t.AppendMessages("OTe_expansionMask", expansionMask[i])
	}
	return r, nil
}

// generateChallenge (*)(Fiat-Shamir) Generates the challenge (χ) using Fiat-Shamir heuristic.
func generateChallenge(t transcripts.Transcript, M int) (challenge Challenge) {
	challengeFiatShamir := make(Challenge, M)
	for i := 0; i < M; i++ {
		bytes, _ := t.ExtractBytes("OTe_challenge_Chi", SigmaBytes)
		copy(challengeFiatShamir[i][:], bytes)
	}
	return challengeFiatShamir
}

// computeResponse Computes the challenge response ẋ, ṫ^i ∀i∈[κ].
func (R *Receiver) computeResponse(extOptions *[2]ExtMessage, challenge Challenge, challengeResponse *ChallengeResponse) {
	M := len(challenge)
	etaBytes := (M * Sigma) / 8 // M = η/σ -> η = M*σ
	// 		ẋ = x_{mσ:(m+1)σ} ...
	copy(challengeResponse.X_val[:], R.extPackedChoices[etaBytes:etaBytes+SigmaBytes])
	// 		                ... + Σ{j=1}^{m} χ_j • xx_{(j-1)σ:jσ}
	for j := 0; j < M; j++ {
		x_hat_j := R.extPackedChoices[j*SigmaBytes : (j+1)*SigmaBytes]
		Chi_j := challenge[j][:]
		for k := 0; k < SigmaBytes; k++ {
			challengeResponse.X_val[k] ^= (Chi_j[k] & x_hat_j[k])
		}
	}
	// 		ṫ^i = ...
	for i := 0; i < Kappa; i++ {
		//         ... t^i_{0,{mσ:(m+1)σ} ...
		copy(challengeResponse.T_val[i][:], extOptions[0][i][etaBytes:etaBytes+SigmaBytes])
		//                           ... + Σ{j=1}^{m} χ_j • t^i_{0,{(j-1)σ:jσ}}
		for j := 0; j < M; j++ {
			t_hat_j := extOptions[0][i][j*SigmaBytes : (j+1)*SigmaBytes]
			Chi_j := challenge[j][:]
			for k := 0; k < SigmaBytes; k++ {
				challengeResponse.T_val[i][k] ^= (Chi_j[k] & t_hat_j[k])
			}
		}
	}
}

// verifyChallenge checks the consistency of the extension.
func (S *Sender) verifyChallenge(
	challenge Challenge,
	challengeResponse *ChallengeResponse,
	extCorrelations *ExtMessage,
) error {
	// Compute sizes
	M := len(challenge)                                // M = η/σ
	etaBytes := (len(extCorrelations[0])) - SigmaBytes // η =  η' - σ
	var qi_val, qi_expected [SigmaBytes]byte
	isCorrect := true
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
		subtle.XORBytes(qi_expected[:], challengeResponse.T_val[i][:], challengeResponse.X_val[:])
		subtle.ConstantTimeCopy((1 - S.baseOtSeeds.RandomChoiceBits[i]), qi_expected[:], challengeResponse.T_val[i][:])
		checkOk := subtle.ConstantTimeCompare(qi_expected[:], qi_val[:]) == 1
		isCorrect = isCorrect && checkOk
	}
	if !isCorrect {
		return errs.NewIdentifiableAbort("receiver", "q_val != q_expected in SoftspokenOT. OTe consistency check failed")
	}
	return nil
}
