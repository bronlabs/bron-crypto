package softspoken

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"math/rand/v2"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

func (r *Receiver) Round1(x []byte) (*Round1P2P, *ReceiverOutput, error) {
	if r.round != 1 {
		return nil, nil, errs.NewRound("Running round %d but participant expected round %d", 1, r.round)
	}
	if len(x)*8 != r.suite.Xi() {
		return nil, nil, errs.NewArgument("choice bits length must be ξ=%d (is %d)", r.suite.Xi(), len(x)*8)
	}

	receiverOutput := &ReceiverOutput{
		ot.ReceiverOutput[[]byte]{
			Choices: x,
		},
	}

	eta := r.suite.L() * r.suite.Xi() // η = L*ξ
	etaBytes := eta / 8
	etaPrimeBytes := etaBytes + SigmaBytes // η'= η + σ

	// EXTENSION
	// step 1.1 & 1.2: Generate x' as a concatenation of L copies of x and σ random bits
	sigmaBits := make([]byte, SigmaBytes)
	_, err := io.ReadFull(r.prng, sigmaBits)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "sampling random bits for Softspoken OTe")
	}
	xPrime := slices.Concat(ot.PackedBits(x).Repeat(r.suite.L()), sigmaBits)

	// step 1.3: Extend the baseOT seeds
	var t [2][Kappa][]byte
	for i := 0; i < Kappa; i++ {
		t[0][i] = make([]byte, etaPrimeBytes) // k_{0,i} --(PRG)--> t_{0,i}
		t[1][i] = make([]byte, etaPrimeBytes) // k_{1,i} --(PRG)--> t_{1,i}
		var prngSeed [32]byte
		subtle.XORBytes(prngSeed[:], r.senderSeeds.Messages[i][0][0], r.sessionId[:])
		prng := rand.NewChaCha8(prngSeed)
		if _, err = io.ReadFull(prng, t[0][i]); err != nil {
			return nil, nil, errs.WrapFailed(err, "bad PRG reading for SoftSpoken OTe")
		}
		subtle.XORBytes(prngSeed[:], r.senderSeeds.Messages[i][1][0], r.sessionId[:])
		prng = rand.NewChaCha8(prngSeed)
		if _, err = io.ReadFull(prng, t[1][i]); err != nil {
			return nil, nil, errs.WrapFailed(err, "bad PRG for SoftSpoken OTe")
		}
	}

	// step 1.4: Compute u_i = t_{0,i} ⊕ t_{1,i} ⊕ x'
	r1 := new(Round1P2P)
	for i := 0; i < Kappa; i++ {
		r1.u[i] = make([]byte, etaPrimeBytes)
		subtle.XORBytes(r1.u[i], t[0][i], t[1][i])
		subtle.XORBytes(r1.u[i], r1.u[i], xPrime)
	}

	//// CONSISTENCY CHECK (Fiat-Shamir)
	//// step 1.5: Generate the challenge (χ) using Fiat-Shamir heuristic
	//for i := 0; i < ot.Kappa; i++ {
	//	r.Transcript.AppendMessages("OTe_expansionMask", r1Out.u[i])
	//}
	//M := eta / Sigma                                          // M = η/σ
	//challengeFiatShamir := generateChallenge(r.Transcript, M) // χ
	//// step 1.6: Compute the challenge response (ẋ, ṫ_i) using the challenge (χ)
	//r.computeResponse(t, challengeFiatShamir, &r1Out.Response)
	//
	//r.Transcript.AppendMessages("OTe_challengeResponse_x_val", r1Out.Response.X_val[:])
	//for i := 0; i < ot.Kappa; i++ {
	//	r.Transcript.AppendMessages("OTe_challengeResponse_t_val", r1Out.Response.T_val[i][:])
	//}

	// RANDOMISE
	// step 1.7: Transpose t_{0,i,j} -> t_{0,j,i}  ∀i∈[κ], j∈[η']
	tj, err := ot.TransposePackedBits(t[0][:])
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "bad transposing t_0 for SoftSpoken COTe")
	}
	// step 1.9: Randomize by hashing t_{0,j,i}  j∈[η'], ∀i∈[κ]

	receiverOutput.Messages = make([][][]byte, r.suite.Xi())
	for j := 0; j < r.suite.Xi(); j++ {
		receiverOutput.Messages[j] = make([][]byte, r.suite.L())
		for l := 0; l < r.suite.L(); l++ {
			//
			digest, err := hashing.Hash(sha256.New, r.sessionId[:], binary.LittleEndian.AppendUint32(nil, uint32(j)), tj[j*r.suite.L()+l])
			if err != nil {
				return nil, nil, errs.WrapHashing(err, "bad hashing t_j for SoftSpoken COTe")
			}
			receiverOutput.Messages[j][l] = digest
		}
	}

	r.round += 2
	return r1, receiverOutput, nil
}

// Round2 uses the PRG to extend the baseOT results and verifies their consistency.
func (s *Sender) Round2(r1 *Round1P2P) (senderOutput *SenderOutput, err error) {
	// Validation
	if s.round != 2 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 2, s.round)
	}
	if err := r1.Validate(s.suite.Xi(), s.suite.L()); err != nil {
		return nil, errs.WrapValidation(err, "invalid round %d input", s.round)
	}

	eta := s.suite.L() * s.suite.Xi()   // η = L*ξ
	etaPrimeBytes := eta/8 + SigmaBytes // η'= η + σ

	// EXTENSION
	// step 2.1: Extend the baseOT seeds
	var tb [Kappa][]byte
	for i := 0; i < Kappa; i++ {
		tb[i] = make([]byte, etaPrimeBytes)
		var prngSeed [32]byte
		subtle.XORBytes(prngSeed[:], s.receiverSeeds.Messages[i][0], s.sessionId[:])
		prng := rand.NewChaCha8(prngSeed)
		if _, err = io.ReadFull(prng, tb[i]); err != nil {
			return nil, errs.WrapFailed(err, "bad PRG write for SoftSpoken OTe")
		}
	}
	// step 2.2: Compute q_i = b_i • u_i + tb_i  ∀i∈[κ]
	extCorrelations := make([][]byte, Kappa)
	qiTemp := make([]byte, etaPrimeBytes)
	for i := 0; i < Kappa; i++ {
		extCorrelations[i] = tb[i]
		subtle.XORBytes(qiTemp, r1.u[i], tb[i])
		c := s.receiverSeeds.Choices[i/8] >> (i % 8) & 0b1
		subtle.ConstantTimeCopy(int(c), extCorrelations[i], qiTemp)
	}

	//// CONSISTENCY CHECK (Fiat-Shamir)
	//// step 2.3: Generate the challenge (χ) using Fiat-Shamir heuristic
	//for i := 0; i < Kappa; i++ {
	//	s.Transcript.AppendMessages("OTe_expansionMask", r1.u[i])
	//}
	//M := eta / Sigma
	//challengeFiatShamir := generateChallenge(s.Transcript, M)
	//// step 2.4: Verify the challenge response (ẋ, ṫ_i) using the challenge (χ)
	//err = s.verifyChallenge(challengeFiatShamir, &r1out.Response, &extCorrelations)
	//if err != nil {
	//	return nil, errs.WrapFailed(err, "bad consistency check for SoftSpoken COTe")
	//}
	//
	//s.Transcript.AppendMessages("OTe_challengeResponse_x_val", r1out.Response.X_val[:])
	//for i := 0; i < ot.Kappa; i++ {
	//	s.Transcript.AppendMessages("OTe_challengeResponse_t_val", r1out.Response.T_val[i][:])
	//}

	// RANDOMISE
	// step 2.5: Transpose q_{i,j} -> q_{j,i}  ∀i∈[κ], j∈[η']
	qjTransposed, err := ot.TransposePackedBits(extCorrelations[:])
	if err != nil {
		return nil, errs.WrapFailed(err, "bad transposing q_{i,j} for SoftSpoken COTe")
	}
	// step 2.6: Randomise by hashing q_{j,i} and q_{j,i}+Δ_i  j∈[η], ∀i∈[κ]
	qjTransposedPlusDelta := make([][]byte, eta)
	for j := 0; j < eta; j++ {
		qjTransposedPlusDelta[j] = make([]byte, Kappa/8)
		// drop last η'-η rows, they are used only for the consistency check
		subtle.XORBytes(qjTransposedPlusDelta[j], qjTransposed[j], s.receiverSeeds.Choices)
	}
	senderOutput = &SenderOutput{
		ot.SenderOutput[[]byte]{
			Messages: make([][2][][]byte, s.suite.Xi()),
		},
	}
	for j := 0; j < s.suite.Xi(); j++ {
		senderOutput.Messages[j][0] = make([][]byte, s.suite.L())
		senderOutput.Messages[j][1] = make([][]byte, s.suite.L())
		for l := 0; l < s.suite.L(); l++ {
			digest, err := hashing.Hash(sha256.New, s.sessionId[:], binary.LittleEndian.AppendUint32(nil, uint32(j)), qjTransposed[j*s.suite.L()+l])
			if err != nil {
				return nil, errs.WrapHashing(err, "bad hashing q_j for SoftSpoken COTe (T&R.2)")
			}
			senderOutput.Messages[j][0][l] = digest
			digest, err = hashing.Hash(sha256.New, s.sessionId[:], binary.LittleEndian.AppendUint32(nil, uint32(j)), qjTransposedPlusDelta[j*s.suite.L()+l])
			if err != nil {
				return nil, errs.WrapHashing(err, "bad hashing q_j_pDelta for SoftSpoken COTe (T&R.2)")
			}
			senderOutput.Messages[j][1][l] = digest
		}
	}

	s.round += 2
	return senderOutput, nil
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

//func generateChallenge(transcript transcripts.Transcript, challengeLength int) (challenge Challenge) {
//	challengeFiatShamir := make(Challenge, challengeLength)
//	for i := 0; i < challengeLength; i++ {
//		bytes, _ := transcript.ExtractBytes("OTe_challenge_Chi", SigmaBytes)
//		copy(challengeFiatShamir[i][:], bytes)
//	}
//	return challengeFiatShamir
//}
//
//// computeResponse Computes the challenge response ẋ, ṫ^i ∀i∈[κ].
//func (r *Receiver) computeResponse(extOptions *[2]ExtMessageBatch, challenge Challenge, challengeResponse *ChallengeResponse) {
//	M := len(challenge)
//	etaBytes := (M * Sigma) / 8 // M = η/σ -> η = M*σ
//	// ẋ = x_{mσ:(m+1)σ} + Σ{k=1}^{m} χ_k • x_{(k-1)σ:kσ}
//	X_val := bf128.NewElementFromBytes(r.xPrime[etaBytes : etaBytes+SigmaBytes])
//	Chi := make([]*bf128.FieldElement, M)
//	for k := 0; k < M; k++ {
//		x_hat_k := bf128.NewElementFromBytes(r.xPrime[k*SigmaBytes : (k+1)*SigmaBytes])
//		Chi[k] = bf128.NewElementFromBytes(challenge[k][:])
//		X_val = X_val.Add(x_hat_k.Mul(Chi[k]))
//	}
//	copy(challengeResponse.X_val[:], X_val.Bytes())
//	// ṫ^i = t^i_{0,{mσ:(m+1)σ} + Σ{k=1}^{m} χ_k • t^i_{0,{(k-1)σ:kσ}}
//	for i := 0; i < ot.Kappa; i++ {
//		T_val := bf128.NewElementFromBytes(extOptions[0][i][etaBytes : etaBytes+SigmaBytes])
//		copy(challengeResponse.T_val[i][:], extOptions[0][i][etaBytes:etaBytes+SigmaBytes])
//		for k := 0; k < M; k++ {
//			t_hat_k := bf128.NewElementFromBytes(extOptions[0][i][k*SigmaBytes : (k+1)*SigmaBytes])
//			T_val = T_val.Add(t_hat_k.Mul(Chi[k]))
//		}
//		copy(challengeResponse.T_val[i][:], T_val.Bytes())
//	}
//}
//
//// verifyChallenge checks the consistency of the extension.
//func (s *Sender) verifyChallenge(
//	challenge Challenge,
//	challengeResponse *ChallengeResponse,
//	extCorrelations *ExtMessageBatch,
//) error {
//	// Compute sizes
//	M := len(challenge)                                // M = η/σ
//	etaBytes := (len(extCorrelations[0])) - SigmaBytes // η =  η' - σ
//	isCorrect := true
//	for i := 0; i < ot.Kappa; i++ {
//		// q̇^i = q^i_hat_{m+1} + Σ{k=1}^{m} χ_k • q^i_hat_k
//		qi_val := bf128.NewElementFromBytes(extCorrelations[i][etaBytes : etaBytes+SigmaBytes])
//		for k := 0; k < M; k++ {
//			qi_hat_k := bf128.NewElementFromBytes(extCorrelations[i][k*SigmaBytes : (k+1)*SigmaBytes])
//			Chi_k := bf128.NewElementFromBytes(challenge[k][:])
//			qi_val = qi_val.Add(qi_hat_k.Mul(Chi_k))
//		}
//		// ABORT if q̇^i != ṫ^i + Δ_i • ẋ  ∀ i ∈[κ]
//		t_val := bf128.NewElementFromBytes(challengeResponse.T_val[i][:])
//		x_val := bf128.NewElementFromBytes(challengeResponse.X_val[:])
//		choice := uint64(s.baseOtSeeds.Choices.Get(uint(i)))
//		qi_expected := bf128.NewField().Select(choice, t_val, t_val.Add(x_val))
//		isCorrect = isCorrect && qi_expected.Equal(qi_val)
//	}
//	if !isCorrect {
//		return errs.NewIdentifiableAbort(s.OtherParty().String(), "q_val != q_expected in SoftspokenOT. OTe consistency check failed")
//	}
//	return nil
//}
