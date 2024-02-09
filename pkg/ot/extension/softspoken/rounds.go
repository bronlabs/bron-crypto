package softspoken

import (
	"crypto/subtle"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/ct"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

type Round1Output struct {
	U        ExtMessageBatch   // [κ][η']bits
	Witness  Witness           // [κ][σ]bits
	Response ChallengeResponse // [σ] + [κ][σ]bits

	_ types.Incomparable
}

// Round1 uses the PRG to extend the baseOT seeds, then proves consistency of the extension.
func (R *Receiver) Round1(x OTeChoices) (oTeReceiverOutput OTeMessageBatch, r1Out *Round1Output, err error) {
	r1Out = &Round1Output{}

	// Sanitise inputs and compute sizes
	if len(x) != (R.Xi >> 3) {
		return nil, nil, errs.NewInvalidArgument("wrong x length (is %d, expected %d)", len(x), R.Xi)
	}
	eta := R.LOTe * R.Xi // η = LOTe*ξ
	etaBytes := eta >> 3
	etaPrimeBytes := etaBytes + SigmaBytes // η'= η + σ

	// EXTENSION
	// step 1.1.1 (Ext.1)
	R.xPrime = make([]byte, etaPrimeBytes)                  // x' ∈ [η']bits
	copy(R.xPrime[:etaBytes], utils.Bits.Repeat(x, R.LOTe)) // x' = {x0 || x0 || ... }_LOTe || {x1 || x1 || ... }_LOTe || ...
	if _, err = R.csrand.Read(R.xPrime[etaBytes:]); err != nil {
		return nil, nil, errs.WrapRandomSampleFailed(err, "sampling random bits for Softspoken OTe (Ext.1)")
	}

	// step 1.1.2 (Ext.2)
	t := &[2]ExtMessageBatch{}
	for i := 0; i < Kappa; i++ {
		t[0][i] = make([]byte, etaPrimeBytes) // k^i_0 --(PRG)--> t^i_0
		t[1][i] = make([]byte, etaPrimeBytes) // k^i_1 --(PRG)--> t^i_1
		if err = R.prg.Seed(R.baseOtSeeds.OneTimePadEncryptionKeys[i][0][:], R.sid); err != nil {
			return nil, nil, errs.WrapFailed(err, "bad PRG seeding for SoftSpoken OTe (Ext.2)")
		}
		if _, err = R.prg.Read(t[0][i]); err != nil {
			return nil, nil, errs.WrapFailed(err, "bad PRG reading for SoftSpoken OTe (Ext.2)")
		}
		if err = R.prg.Seed(R.baseOtSeeds.OneTimePadEncryptionKeys[i][1][:], R.sid); err != nil {
			return nil, nil, errs.WrapFailed(err, "bad PRG for SoftSpoken OTe (Ext.2)")
		}
		if _, err = R.prg.Read(t[1][i]); err != nil {
			return nil, nil, errs.WrapFailed(err, "bad PRG for SoftSpoken OTe (Ext.2)")
		}
	}
	// step 1.1.3 (Ext.3)
	for i := 0; i < Kappa; i++ {
		r1Out.U[i] = make([]byte, etaPrimeBytes) // u_i = t^i_0 + t^i_1 + Δ_i
		subtle.XORBytes(r1Out.U[i], t[0][i], t[1][i])
		subtle.XORBytes(r1Out.U[i], r1Out.U[i], R.xPrime)
	}

	// CONSISTENCY CHECK
	// step 1.2.1.[1-2] (*)(Check.1, Fiat-Shamir)
	r1Out.Witness, err = commitWitness(R.transcript, &r1Out.U, nil, R.csrand)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "bad commitment for SoftSpoken COTe (Check.1)")
	}
	// step 1.2.1.3 (*)(Check.1, Fiat-Shamir)
	M := eta / Sigma                                          // M = η/σ
	challengeFiatShamir := generateChallenge(R.transcript, M) // χ
	// step 1.2.2 (Check.2) Compute ẋ and ṫ
	R.computeResponse(t, challengeFiatShamir, &r1Out.Response)

	// (*)(Fiat-Shamir): Append the challenge response to the transcript (to be used by protocols sharing the transcript)
	R.transcript.AppendMessages("OTe_challengeResponse_x_val", r1Out.Response.X_val[:])
	for i := 0; i < Kappa; i++ {
		R.transcript.AppendMessages("OTe_challengeResponse_t_val", r1Out.Response.T_val[i][:])
	}

	// TRANSPOSE AND RANDOMISE
	// step 1.3.1 (T&R.1) Transpose t^i_0 into t_j
	t_j, err := utils.Bits.TransposePacked(t[0][:]) // t_j ∈ [η'][κ]bits
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "bad transposing t^i_0 for SoftSpoken COTe")
	}
	// step 1.3.2 (T&R.2) Hash η rows of t_j using the sid as salt (drop η' - η rows, used for consistency check)
	R.oTeReceiverOutput = make(OTeMessageBatch, R.Xi)
	for j := 0; j < R.Xi; j++ {
		R.oTeReceiverOutput[j] = make(OTeMessage, R.LOTe*KappaBytes)
	}
	err = HashSalted(R.sid, t_j[:eta], R.oTeReceiverOutput)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "bad hashing t_j for SoftSpoken COTe (T&R.2)")
	}
	return R.oTeReceiverOutput, r1Out, nil
}

// Round2Output is the sender's output of round2 of COTe, to be sent to the Receiver.
type Round2Output struct {
	Tau COTeMessageBatch

	_ types.Incomparable
}

// Round2 uses the PRG to extend the baseOT results, verifies their consistency
// and (COTe only, not in OTe) derandomizes them. Set cOTeSenderInput (α) to nil
// for OTe functionality.
func (S *Sender) Round2(r1out *Round1Output, cOTeSenderInput COTeMessageBatch,
) (oTeSenderOutput *[2]OTeMessageBatch, cOTeSenderOutput COTeMessageBatch, r2out *Round2Output, err error) {
	// Sanitise inputs, compute sizes
	if r1out == nil || len(r1out.U) != Kappa || len(r1out.Witness) != Kappa ||
		len(r1out.Response.T_val) != Kappa || len(r1out.Response.X_val) != SigmaBytes {

		return nil, nil, nil, errs.NewInvalidLength("wrong r1out length (U (%d - %d), Witness (%d - %d), T_val (%d - %d), X_val (%d - %d))",
			len(r1out.U), Kappa, len(r1out.Witness), Kappa, len(r1out.Response.T_val), Kappa, len(r1out.Response.X_val), SigmaBytes)
	}
	Eta := S.LOTe * S.Xi                // η = LOTe*ξ
	EtaPrimeBytes := Eta/8 + SigmaBytes // η'= η + σ

	// EXTENSION
	// step 2.1.1 (Ext.1) k^i_{Δ_i} --(PRG)--> t^i_{Δ_i}
	t_Delta := ExtMessageBatch{}
	for i := 0; i < Kappa; i++ {
		t_Delta[i] = make([]byte, EtaPrimeBytes)
		if err = S.prg.Seed(S.baseOtSeeds.OneTimePadDecryptionKey[i][:], S.sid); err != nil {
			return nil, nil, nil, errs.WrapFailed(err, "bad PRG reset for SoftSpoken OTe (Ext.2)")
		}
		if _, err = S.prg.Read(t_Delta[i]); err != nil {
			return nil, nil, nil, errs.WrapFailed(err, "bad PRG write for SoftSpoken OTe (Ext.2)")
		}
	}
	// step 2.1.2 (Ext.2) Compute q_i = Δ_i • u_i + t_i
	extCorrelations := ExtMessageBatch{}
	qiTemp := make([]byte, EtaPrimeBytes)
	for i := 0; i < Kappa; i++ {
		if len(r1out.U[i]) != EtaPrimeBytes {
			return nil, nil, nil, errs.NewInvalidLength("U[%d] length is %d, should be %d", i, len(r1out.U[i]), EtaPrimeBytes)
		}
		extCorrelations[i] = t_Delta[i]
		subtle.XORBytes(qiTemp, r1out.U[i], t_Delta[i])
		subtle.ConstantTimeCopy(S.baseOtSeeds.RandomChoiceBits[i], extCorrelations[i], qiTemp)
	}

	// CONSISTENCY CHECK
	// step 2.2.1.1 (*)(Fiat-Shamir): Append the expansionMask to the transcript
	_, err = commitWitness(S.transcript, &r1out.U, r1out.Witness, S.csrand)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "bad commitment for SoftSpoken COTe (Check.1)")
	}
	// step 2.2.1.2 (Check.1&2) Generate the challenge (χ) using Fiat-Shamir heuristic
	M := Eta / Sigma
	challengeFiatShamir := generateChallenge(S.transcript, M)
	// step 2.2.[2-3] (Check.3) Check the consistency of the challenge response computing q^i
	err = S.verifyChallenge(challengeFiatShamir, &r1out.Response, &extCorrelations)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "bad consistency check for SoftSpoken COTe (Check.3)")
	}
	// (*)(Fiat-Shamir): Append the challenge response to the transcript
	S.transcript.AppendMessages("OTe_challengeResponse_x_val", r1out.Response.X_val[:])
	for i := 0; i < Kappa; i++ {
		S.transcript.AppendMessages("OTe_challengeResponse_t_val", r1out.Response.T_val[i][:])
	}

	// TRANSPOSE AND RANDOMISE
	// step 2.3.1 (T&R.1) Transpose q^i -> q_j and add Δ -> q_j+Δ
	qjTransposed, err := utils.Bits.TransposePacked(extCorrelations[:]) // q_j ∈ [η'][κ]bits
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "bad transposing q^i for SoftSpoken COTe")
	}
	qjTransposedPlusDelta := make([][]byte, Eta) // q_j+Δ ∈ [η][κ]bits
	for j := 0; j < Eta; j++ {
		qjTransposedPlusDelta[j] = make([]byte, KappaBytes)
		// drop last η'-η rows, they are used only for the consistency check
		subtle.XORBytes(qjTransposedPlusDelta[j], qjTransposed[j], S.baseOtSeeds.PackedRandomChoiceBits)
	}
	// step 2.3.2 (T&R.2) Randomise by hashing q_j and q_j+Δ
	oTeSenderOutput = &[2]OTeMessageBatch{make(OTeMessageBatch, S.Xi), make(OTeMessageBatch, S.Xi)}
	for j := 0; j < S.Xi; j++ {
		oTeSenderOutput[0][j] = make(OTeMessage, S.LOTe*KappaBytes)
		oTeSenderOutput[1][j] = make(OTeMessage, S.LOTe*KappaBytes)
	}
	err = HashSalted(S.sid, qjTransposed[:Eta], oTeSenderOutput[0])
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "bad hashing q_j for SoftSpoken COTe (T&R.2)")
	}
	err = HashSalted(S.sid, qjTransposedPlusDelta[:Eta], oTeSenderOutput[1])
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "bad hashing q_j_pDelta for SoftSpoken COTe (T&R.2)")
	}

	// Return OTe and avoid derandomising if the input opts are not provided
	if len(cOTeSenderInput) == 0 {
		return oTeSenderOutput, nil, nil, nil
	}

	// DERANDOMISE
	// step 2.4. (Derand)
	if len(cOTeSenderInput) != S.Xi {
		return nil, nil, nil, errs.NewInvalidArgument("wrong cOTeSenderInput lengths (is %d, expected %d)",
			len(cOTeSenderInput), S.Xi)
	}
	cOTeSenderOutput = make(COTeMessageBatch, S.Xi)
	r2out = &Round2Output{Tau: make(COTeMessageBatch, S.Xi)}
	for j := 0; j < S.Xi; j++ {
		if len(cOTeSenderInput[j]) != S.LOTe {
			return nil, nil, nil, errs.NewInvalidLength("wrong cOTeSenderInput[%d] length (is %d, expected %d)",
				j, len(cOTeSenderInput[j]), S.LOTe)
		}
		cOTeSenderOutput[j] = make([]curves.Scalar, S.LOTe)
		r2out.Tau[j] = make([]curves.Scalar, S.LOTe)
		for l := 0; l < S.LOTe; l++ {
			// step 2.4.1   z_A_j = ECS(v_0_j)
			cOTeSenderOutput[j][l], err = S.curve.Scalar().ScalarField().Hash(oTeSenderOutput[0][j][l*KappaBytes : (l+1)*KappaBytes])
			if err != nil {
				return nil, nil, nil, errs.WrapHashingFailed(err, "bad hashing v_0_j for SoftSpoken COTe (Derand.1)")
			}
			// step 2.4.2   τ_j = ECS(v_1_j)...
			r2out.Tau[j][l], err = S.curve.Scalar().ScalarField().Hash(oTeSenderOutput[1][j][l*KappaBytes : (l+1)*KappaBytes])
			if err != nil {
				return nil, nil, nil, errs.WrapHashingFailed(err, "bad hashing v_1_j for SoftSpoken COTe (Derand.1)")
			}
			//                              ... - z_A_j + α_j
			r2out.Tau[j][l] = r2out.Tau[j][l].
				Sub(cOTeSenderOutput[j][l]).Add(cOTeSenderInput[j][l])
		}
	}

	// (*)(Fiat-Shamir): Append the derandomization mask to the transcript
	for j := 0; j < S.Xi; j++ {
		for l := 0; l < S.LOTe; l++ {
			S.transcript.AppendMessages("OTe_derandMask", r2out.Tau[j][l].Bytes())
		}
	}

	return oTeSenderOutput, cOTeSenderOutput, r2out, nil
}

// Round3 uses the derandomization mask to derandomize the COTe output.
func (R *Receiver) Round3(r2out *Round2Output) (cOTeReceiverOutput COTeMessageBatch, err error) {
	// Sanitise input, compute sizes
	if (r2out == nil) || (len(r2out.Tau) != R.Xi) {
		return nil, errs.NewIsNil("nil in input arguments of Softspoken Round3")
	}

	// (*)(Fiat-Shamir): Append the derandomization mask to the transcript
	for j := 0; j < R.Xi; j++ {
		if len(r2out.Tau[j]) != R.LOTe {
			return nil, errs.NewInvalidLength("wrong r2out.DerandMask[%d] length (is %d, should be %d)",
				j, len(r2out.Tau[0]), R.LOTe)
		}
		for l := 0; l < R.LOTe; l++ {
			R.transcript.AppendMessages("OTe_derandMask", r2out.Tau[j][l].Bytes())
		}
	}

	// step 3.1 (Derand)
	cOTeReceiverOutput = make(COTeMessageBatch, R.Xi)
	for j := 0; j < R.Xi; j++ {
		cOTeReceiverOutput[j] = make([]curves.Scalar, R.LOTe)
		for l := 0; l < R.LOTe; l++ {
			minus_v_x, err := R.curve.Scalar().ScalarField().Hash(R.oTeReceiverOutput[j][l*KappaBytes : (l+1)*KappaBytes])
			if err != nil {
				return nil, errs.WrapHashingFailed(err, "bad hashing v_x_j for SoftSpoken COTe (Derand.2)")
			}
			minus_v_x = minus_v_x.Neg()
			bit, err := utils.Bits.Select(R.xPrime, j*R.LOTe+l)
			if err != nil {
				return nil, errs.WrapFailed(err, "cannot select bit")
			}
			// z_B_j = τ_j - ECS(v_x_j)  if x_j == 1
			//       =     - ECS(v_x_j)  if x_j == 0
			cOTeReceiverOutput[j][l] = ct.ConstantTimeSelectScalar(int(bit), r2out.Tau[j][l].Add(minus_v_x), minus_v_x)
		}
	}
	return cOTeReceiverOutput, nil
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
func commitWitness(t transcripts.Transcript, expansionMask *ExtMessageBatch, r Witness, csrand io.Reader) (Witness, error) {
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
func (R *Receiver) computeResponse(extOptions *[2]ExtMessageBatch, challenge Challenge, challengeResponse *ChallengeResponse) {
	M := len(challenge)
	etaBytes := (M * Sigma) / 8 // M = η/σ -> η = M*σ
	// 		ẋ = x_{mσ:(m+1)σ} ...
	copy(challengeResponse.X_val[:], R.xPrime[etaBytes:etaBytes+SigmaBytes])
	// 		                ... + Σ{k=1}^{m} χ_j • xx_{(k-1)σ:kσ}
	for k := 0; k < M; k++ {
		x_hat_j := R.xPrime[k*SigmaBytes : (k+1)*SigmaBytes]
		Chi_j := challenge[k][:]
		for k := 0; k < SigmaBytes; k++ {
			challengeResponse.X_val[k] ^= (Chi_j[k] & x_hat_j[k])
		}
	}
	// 		ṫ^i = ...
	for i := 0; i < Kappa; i++ {
		//         ... t^i_{0,{mσ:(m+1)σ} ...
		copy(challengeResponse.T_val[i][:], extOptions[0][i][etaBytes:etaBytes+SigmaBytes])
		//                           ... + Σ{k=1}^{m} χ_j • t^i_{0,{(k-1)σ:kσ}}
		for k := 0; k < M; k++ {
			t_hat_j := extOptions[0][i][k*SigmaBytes : (k+1)*SigmaBytes]
			Chi_j := challenge[k][:]
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
	extCorrelations *ExtMessageBatch,
) error {
	// Compute sizes
	M := len(challenge)                                // M = η/σ
	etaBytes := (len(extCorrelations[0])) - SigmaBytes // η =  η' - σ
	var qi_val, qi_expected [SigmaBytes]byte
	isCorrect := true
	for i := 0; i < Kappa; i++ {
		// q̇^i = q^i_hat_{m+1} ...
		copy(qi_val[:], extCorrelations[i][etaBytes:etaBytes+SigmaBytes])
		//                     ... + Σ{k=1}^{m} χ_j • q^i_hat_j
		for k := 0; k < M; k++ {
			qi_hat_j := extCorrelations[i][k*SigmaBytes : (k+1)*SigmaBytes]
			Chi_j := challenge[k][:]
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
