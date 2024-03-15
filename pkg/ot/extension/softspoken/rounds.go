package softspoken

import (
	"crypto/subtle"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/binaryfield/bf128"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

// Round1 uses the PRG to extend the baseOT seeds, then proves consistency of the extension.
func (r *Receiver) Round1(x ot.PackedBits) (oTeReceiverOutput []ot.Message, r1Out *Round1Output, err error) {
	// Validation
	if err := r.InRound(1); err != nil {
		return nil, nil, errs.WrapValidation(err, "Participant in invalid round")
	}
	if len(x) != r.Xi/8 {
		return nil, nil, errs.NewArgument("choice bits length must be ξ=%d (is %d)", r.Xi, len(x))
	}

	r1Out = &Round1Output{}

	r.Output.Choices = x
	eta := r.L * r.Xi // η = L*ξ
	etaBytes := eta >> 3
	etaPrimeBytes := etaBytes + SigmaBytes // η'= η + σ

	// EXTENSION
	// step 1.1 & 1.2: Generate x' as a concatenation of L copies of x and σ random bits
	r.xPrime = make([]byte, etaPrimeBytes)
	copy(r.xPrime[:etaBytes], bitstring.RepeatBits(x, r.L)) // x' = {x0 || x0 || ... }_L || {x1 || x1 || ... }_L || ...
	if _, err = io.ReadFull(r.Prng(), r.xPrime[etaBytes:]); err != nil {
		return nil, nil, errs.WrapRandomSample(err, "sampling random bits for Softspoken OTe")
	}

	// step 1.3: Extend the baseOT seeds
	t := &[2]ExtMessageBatch{}
	for i := 0; i < ot.Kappa; i++ {
		t[0][i] = make([]byte, etaPrimeBytes) // k_{0,i} --(PRG)--> t_{0,i}
		t[1][i] = make([]byte, etaPrimeBytes) // k_{1,i} --(PRG)--> t_{1,i}
		if err = r.prg.Seed(r.baseOtSeeds.MessagePairs[i][0][0][:], r.SessionId()); err != nil {
			return nil, nil, errs.WrapFailed(err, "bad PRG seeding for SoftSpoken OTe")
		}
		if _, err = io.ReadFull(r.prg, t[0][i]); err != nil {
			return nil, nil, errs.WrapFailed(err, "bad PRG reading for SoftSpoken OTe")
		}
		if err = r.prg.Seed(r.baseOtSeeds.MessagePairs[i][1][0][:], r.SessionId()); err != nil {
			return nil, nil, errs.WrapFailed(err, "bad PRG for SoftSpoken OTe")
		}
		if _, err = io.ReadFull(r.prg, t[1][i]); err != nil {
			return nil, nil, errs.WrapFailed(err, "bad PRG for SoftSpoken OTe")
		}
	}
	// step 1.4: Compute u_i = t_{0,i} ⊕ t_{1,i} ⊕ x'
	for i := 0; i < ot.Kappa; i++ {
		r1Out.U[i] = make([]byte, etaPrimeBytes)
		subtle.XORBytes(r1Out.U[i], t[0][i], t[1][i])
		subtle.XORBytes(r1Out.U[i], r1Out.U[i], r.xPrime)
	}

	// CONSISTENCY CHECK (Fiat-Shamir)
	// step 1.5: Generate the challenge (χ) using Fiat-Shamir heuristic
	for i := 0; i < ot.Kappa; i++ {
		r.Transcript().AppendMessages("OTe_expansionMask", r1Out.U[i])
	}
	M := eta / Sigma                                            // M = η/σ
	challengeFiatShamir := generateChallenge(r.Transcript(), M) // χ
	// step 1.6: Compute the challenge response (ẋ, ṫ_i) using the challenge (χ)
	r.computeResponse(t, challengeFiatShamir, &r1Out.Response)

	r.Transcript().AppendMessages("OTe_challengeResponse_x_val", r1Out.Response.X_val[:])
	for i := 0; i < ot.Kappa; i++ {
		r.Transcript().AppendMessages("OTe_challengeResponse_t_val", r1Out.Response.T_val[i][:])
	}

	// RANDOMISE
	// step 1.7: Transpose t_{0,i,j} -> t_{0,j,i}  ∀i∈[κ], j∈[η']
	t_j, err := bitstring.TransposePackedBits(t[0][:])
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "bad transposing t_0 for SoftSpoken COTe")
	}
	// step 1.9: Randomise by hashing t_{0,j,i}  j∈[η'], ∀i∈[κ]
	r.Output.ChosenMessages = make([]ot.Message, r.Xi)
	for j := 0; j < r.Xi; j++ {
		r.Output.ChosenMessages[j] = make(ot.Message, r.L)
		for l := 0; l < r.L; l++ {
			digest, err := hashing.Hash(ot.HashFunction, []byte(transcriptLabel), r.SessionId(), bitstring.ToBytesLE(j), t_j[j*r.L+l])
			if err != nil {
				return nil, nil, errs.WrapHashing(err, "bad hashing t_j for SoftSpoken COTe")
			}
			copy(r.Output.ChosenMessages[j][l][:], digest)
		}
	}

	r.LastRound()
	return r.Output.ChosenMessages, r1Out, nil
}

// Round2 uses the PRG to extend the baseOT results and verifies their consistency.
func (s *Sender) Round2(r1out *Round1Output) (oTeSenderOutput [][2]ot.Message, err error) {
	// Validation
	if err := s.InRound(2); err != nil {
		return nil, errs.WrapValidation(err, "Participant in invalid round")
	}
	if err := network.ValidateMessage(r1out, s.L, s.Xi); err != nil {
		return nil, errs.WrapValidation(err, "invalid round %d input", s.Round())
	}

	Eta := s.L * s.Xi                   // η = L*ξ
	EtaPrimeBytes := Eta/8 + SigmaBytes // η'= η + σ

	// EXTENSION
	// step 2.1: Extend the baseOT seeds
	t_b := ExtMessageBatch{}
	for i := 0; i < ot.Kappa; i++ {
		t_b[i] = make([]byte, EtaPrimeBytes)
		if err = s.prg.Seed(s.baseOtSeeds.ChosenMessages[i][0][:], s.SessionId()); err != nil {
			return nil, errs.WrapFailed(err, "bad PRG reset for SoftSpoken OTe")
		}
		if _, err = io.ReadFull(s.prg, t_b[i]); err != nil {
			return nil, errs.WrapFailed(err, "bad PRG write for SoftSpoken OTe")
		}
	}
	// step 2.2: Compute q_i = b_i • u_i + tb_i  ∀i∈[κ]
	extCorrelations := ExtMessageBatch{}
	qiTemp := make([]byte, EtaPrimeBytes)
	for i := 0; i < ot.Kappa; i++ {
		extCorrelations[i] = t_b[i]
		subtle.XORBytes(qiTemp, r1out.U[i], t_b[i])
		subtle.ConstantTimeCopy(int(s.baseOtSeeds.Choices.Select(i)), extCorrelations[i], qiTemp)
	}

	// CONSISTENCY CHECK (Fiat-Shamir)
	// step 2.3: Generate the challenge (χ) using Fiat-Shamir heuristic
	for i := 0; i < ot.Kappa; i++ {
		s.Transcript().AppendMessages("OTe_expansionMask", r1out.U[i])
	}
	M := Eta / Sigma
	challengeFiatShamir := generateChallenge(s.Transcript(), M)
	// step 2.4: Verify the challenge response (ẋ, ṫ_i) using the challenge (χ)
	err = s.verifyChallenge(challengeFiatShamir, &r1out.Response, &extCorrelations)
	if err != nil {
		return nil, errs.WrapFailed(err, "bad consistency check for SoftSpoken COTe")
	}

	s.Transcript().AppendMessages("OTe_challengeResponse_x_val", r1out.Response.X_val[:])
	for i := 0; i < ot.Kappa; i++ {
		s.Transcript().AppendMessages("OTe_challengeResponse_t_val", r1out.Response.T_val[i][:])
	}

	// RANDOMISE
	// step 2.5: Transpose q_{i,j} -> q_{j,i}  ∀i∈[κ], j∈[η']
	qjTransposed, err := bitstring.TransposePackedBits(extCorrelations[:])
	if err != nil {
		return nil, errs.WrapFailed(err, "bad transposing q_{i,j} for SoftSpoken COTe")
	}
	// step 2.6: Randomise by hashing q_{j,i} and q_{j,i}+Δ_i  j∈[η], ∀i∈[κ]
	qjTransposedPlusDelta := make([][]byte, Eta)
	for j := 0; j < Eta; j++ {
		qjTransposedPlusDelta[j] = make([]byte, ot.KappaBytes)
		// drop last η'-η rows, they are used only for the consistency check
		subtle.XORBytes(qjTransposedPlusDelta[j], qjTransposed[j], s.baseOtSeeds.Choices)
	}
	s.Output.MessagePairs = make([][2]ot.Message, s.Xi)
	for j := 0; j < s.Xi; j++ {
		s.Output.MessagePairs[j][0] = make(ot.Message, s.L)
		s.Output.MessagePairs[j][1] = make(ot.Message, s.L)
		for l := 0; l < s.L; l++ {
			digest, err := hashing.Hash(ot.HashFunction, []byte(transcriptLabel), s.SessionId(), bitstring.ToBytesLE(j), qjTransposed[j*s.L+l])
			if err != nil {
				return nil, errs.WrapHashing(err, "bad hashing q_j for SoftSpoken COTe (T&R.2)")
			}
			copy(s.Output.MessagePairs[j][0][l][:], digest)
			digest, err = hashing.Hash(ot.HashFunction, []byte(transcriptLabel), s.SessionId(), bitstring.ToBytesLE(j), qjTransposedPlusDelta[j*s.L+l])
			if err != nil {
				return nil, errs.WrapHashing(err, "bad hashing q_j_pDelta for SoftSpoken COTe (T&R.2)")
			}
			copy(s.Output.MessagePairs[j][1][l][:], digest)
		}
	}

	s.LastRound()
	return s.Output.MessagePairs, nil
}

// -------------------------------------------------------------------------- //
// --------------------------  CONSISTENCY CHECK ---------------------------- //
// -------------------------------------------------------------------------- //
// This section contains the functions for the fiat-shamir consistency check:
// 1. generateChallenge: the verifier generates the challenge (χ).
// 2. computeResponse: the prover computes the challenge response (ẋ, ṫ^i)
//    using the challenge (χ).
// 3. verifyChallenge: the verifier verifies the challenge response (ẋ, ṫ^i)
//    using the challenge (χ) and the commitment to the statement (u_i).
//

func generateChallenge(transcript transcripts.Transcript, M int) (challenge Challenge) {
	challengeFiatShamir := make(Challenge, M)
	for i := 0; i < M; i++ {
		bytes, _ := transcript.ExtractBytes("OTe_challenge_Chi", SigmaBytes)
		copy(challengeFiatShamir[i][:], bytes)
	}
	return challengeFiatShamir
}

// computeResponse Computes the challenge response ẋ, ṫ^i ∀i∈[κ].
func (r *Receiver) computeResponse(extOptions *[2]ExtMessageBatch, challenge Challenge, challengeResponse *ChallengeResponse) {
	M := len(challenge)
	etaBytes := (M * Sigma) / 8 // M = η/σ -> η = M*σ
	// ẋ = x_{mσ:(m+1)σ} + Σ{k=1}^{m} χ_k • x_{(k-1)σ:kσ}
	X_val := bf128.NewElementFromBytes(r.xPrime[etaBytes : etaBytes+SigmaBytes])
	Chi := make([]*bf128.FieldElement, M)
	for k := 0; k < M; k++ {
		x_hat_k := bf128.NewElementFromBytes(r.xPrime[k*SigmaBytes : (k+1)*SigmaBytes])
		Chi[k] = bf128.NewElementFromBytes(challenge[k][:])
		X_val = X_val.Add(x_hat_k.Mul(Chi[k]))
	}
	copy(challengeResponse.X_val[:], X_val.Bytes())
	// ṫ^i = t^i_{0,{mσ:(m+1)σ} + Σ{k=1}^{m} χ_k • t^i_{0,{(k-1)σ:kσ}}
	for i := 0; i < ot.Kappa; i++ {
		T_val := bf128.NewElementFromBytes(extOptions[0][i][etaBytes : etaBytes+SigmaBytes])
		copy(challengeResponse.T_val[i][:], extOptions[0][i][etaBytes:etaBytes+SigmaBytes])
		for k := 0; k < M; k++ {
			t_hat_k := bf128.NewElementFromBytes(extOptions[0][i][k*SigmaBytes : (k+1)*SigmaBytes])
			T_val = T_val.Add(t_hat_k.Mul(Chi[k]))
		}
		copy(challengeResponse.T_val[i][:], T_val.Bytes())
	}
}

// verifyChallenge checks the consistency of the extension.
func (s *Sender) verifyChallenge(
	challenge Challenge,
	challengeResponse *ChallengeResponse,
	extCorrelations *ExtMessageBatch,
) error {
	// Compute sizes
	M := len(challenge)                                // M = η/σ
	etaBytes := (len(extCorrelations[0])) - SigmaBytes // η =  η' - σ
	isCorrect := true
	for i := 0; i < ot.Kappa; i++ {
		// q̇^i = q^i_hat_{m+1} + Σ{k=1}^{m} χ_k • q^i_hat_k
		qi_val := bf128.NewElementFromBytes(extCorrelations[i][etaBytes : etaBytes+SigmaBytes])
		for k := 0; k < M; k++ {
			qi_hat_k := bf128.NewElementFromBytes(extCorrelations[i][k*SigmaBytes : (k+1)*SigmaBytes])
			Chi_k := bf128.NewElementFromBytes(challenge[k][:])
			qi_val = qi_val.Add(qi_hat_k.Mul(Chi_k))
		}
		// ABORT if q̇^i != ṫ^i + Δ_i • ẋ  ∀ i ∈[κ]
		t_val := bf128.NewElementFromBytes(challengeResponse.T_val[i][:])
		x_val := bf128.NewElementFromBytes(challengeResponse.X_val[:])
		qi_expected := bf128.NewField().Select(s.baseOtSeeds.Choices.Select(i) != 0, t_val, t_val.Add(x_val))
		isCorrect = isCorrect && qi_expected.Equal(qi_val)
	}
	if !isCorrect {
		return errs.NewIdentifiableAbort(s.OtherParty().String(), "q_val != q_expected in SoftspokenOT. OTe consistency check failed")
	}
	return nil
}
