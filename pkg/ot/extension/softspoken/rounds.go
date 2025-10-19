package softspoken

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"math/rand/v2"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/binaryfields/bf128"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
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
		r1.U[i] = make([]byte, etaPrimeBytes)
		subtle.XORBytes(r1.U[i], t[0][i], t[1][i])
		subtle.XORBytes(r1.U[i], r1.U[i], xPrime)
	}

	// CONSISTENCY CHECK (Fiat-Shamir)
	// step 1.5: Generate the challenge (χ) using Fiat-Shamir heuristic
	for i := 0; i < Kappa; i++ {
		r.tape.AppendBytes(expansionMaskLabel, r1.U[i])
	}
	m := eta / Sigma                                    // M = η/σ
	challengeFiatShamir := generateChallenge(r.tape, m) // χ
	// step 1.6: Compute the challenge response (ẋ, ṫ_i) using the challenge (χ)
	err = r.computeResponse(xPrime, &t, challengeFiatShamir, &r1.ChallengeResponse)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot compute challenge")
	}

	r.tape.AppendBytes(challengeResponseXLabel, r1.ChallengeResponse.X[:])
	for i := 0; i < Kappa; i++ {
		r.tape.AppendBytes(challengeResponseTLabel, r1.ChallengeResponse.T[i][:])
	}

	// RANDOMISE
	// step 1.7: Transpose t_{0,i,j} -> t_{0,j,i}  ∀i∈[κ], j∈[η']
	tj, err := ot.TransposePackedBits(t[0][:])
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "bad transposing t_0 for SoftSpoken COTe")
	}
	// step 1.9: Randomise by hashing t_{0,j,i}  j∈[η'], ∀i∈[κ]

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
		subtle.XORBytes(qiTemp, r1.U[i], tb[i])
		c := s.receiverSeeds.Choices[i/8] >> (i % 8) & 0b1
		subtle.ConstantTimeCopy(int(c), extCorrelations[i], qiTemp)
	}

	// CONSISTENCY CHECK (Fiat-Shamir)
	// step 2.3: Generate the challenge (χ) using Fiat-Shamir heuristic
	for i := 0; i < Kappa; i++ {
		s.tape.AppendBytes(expansionMaskLabel, r1.U[i])
	}
	M := eta / Sigma
	challengeFiatShamir := generateChallenge(s.tape, M)
	// step 2.4: Verify the challenge response (ẋ, ṫ_i) using the challenge (χ)
	err = s.verifyChallenge(challengeFiatShamir, &r1.ChallengeResponse, extCorrelations)
	if err != nil {
		return nil, errs.WrapFailed(err, "bad consistency check for SoftSpoken COTe")
	}

	s.tape.AppendBytes(challengeResponseXLabel, r1.ChallengeResponse.X[:])
	for i := 0; i < Kappa; i++ {
		s.tape.AppendBytes(challengeResponseTLabel, r1.ChallengeResponse.T[i][:])
	}

	// RANDOMISE
	// step 2.5: Transpose q_{i,j} -> q_{j,i}  ∀i∈[κ], j∈[η']
	qjTransposed, err := ot.TransposePackedBits(extCorrelations)
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

func generateChallenge(transcript transcripts.Transcript, challengeLength int) (challenge Challenge) {
	challengeFiatShamir := make(Challenge, challengeLength)
	for i := 0; i < challengeLength; i++ {
		bytes, _ := transcript.ExtractBytes("OTe_challenge_Chi", SigmaBytes)
		copy(challengeFiatShamir[i][:], bytes)
	}
	return challengeFiatShamir
}

// computeResponse Computes the challenge response ẋ, ṫ^i ∀i∈[κ].
func (r *Receiver) computeResponse(xPrime []byte, extOptions *[2][Kappa][]byte, challenge Challenge, challengeResponse *ChallengeResponse) error {
	m := len(challenge)
	etaBytes := (m * Sigma) / 8 // M = η/σ -> η = M*σ
	// ẋ = x_{mσ:(m+1)σ} + Σ{k=1}^{m} χ_k • x_{(k-1)σ:kσ}
	x, err := bf128.NewField().FromBytes(xPrime[etaBytes : etaBytes+SigmaBytes])
	if err != nil {
		return errs.NewFailed("cannot create field element")
	}
	chi := make([]*bf128.FieldElement, m)
	for k := 0; k < m; k++ {
		xHatK, err := bf128.NewField().FromBytes(xPrime[k*SigmaBytes : (k+1)*SigmaBytes])
		if err != nil {
			return errs.NewFailed("cannot create field element")
		}
		chi[k], err = bf128.NewField().FromBytes(challenge[k][:])
		if err != nil {
			return errs.NewFailed("cannot create field element")
		}
		x = x.Add(xHatK.Mul(chi[k]))
	}
	copy(challengeResponse.X[:], x.Bytes())
	// ṫ^i = t^i_{0,{mσ:(m+1)σ} + Σ{k=1}^{m} χ_k • t^i_{0,{(k-1)σ:kσ}}
	for i := 0; i < Kappa; i++ {
		t, err := bf128.NewField().FromBytes(extOptions[0][i][etaBytes : etaBytes+SigmaBytes])
		if err != nil {
			return errs.NewFailed("cannot create field element")
		}
		copy(challengeResponse.T[i][:], extOptions[0][i][etaBytes:etaBytes+SigmaBytes])
		for k := 0; k < m; k++ {
			tHatK, err := bf128.NewField().FromBytes(extOptions[0][i][k*SigmaBytes : (k+1)*SigmaBytes])
			if err != nil {
				return errs.NewFailed("cannot create field element")
			}
			t = t.Add(tHatK.Mul(chi[k]))
		}
		copy(challengeResponse.T[i][:], t.Bytes())
	}

	return nil
}

// verifyChallenge checks the consistency of the extension.
func (s *Sender) verifyChallenge(
	challenge Challenge,
	challengeResponse *ChallengeResponse,
	extCorrelations [][]byte,
) error {
	// Compute sizes
	m := len(challenge)                                // M = η/σ
	etaBytes := (len(extCorrelations[0])) - SigmaBytes // η =  η' - σ
	isCorrect := true
	for i := 0; i < Kappa; i++ {
		// q̇^i = q^i_hat_{m+1} + Σ{k=1}^{m} χ_k • q^i_hat_k
		qi, err := bf128.NewField().FromBytes(extCorrelations[i][etaBytes : etaBytes+SigmaBytes])
		if err != nil {
			return errs.NewFailed("cannot create field element")
		}
		for k := 0; k < m; k++ {
			qiHatK, err := bf128.NewField().FromBytes(extCorrelations[i][k*SigmaBytes : (k+1)*SigmaBytes])
			if err != nil {
				return errs.NewFailed("cannot create field element")
			}
			chiK, err := bf128.NewField().FromBytes(challenge[k][:])
			if err != nil {
				return errs.NewFailed("cannot create field element")
			}
			qi = qi.Add(qiHatK.Mul(chiK))
		}
		// ABORT if q̇^i != ṫ^i + Δ_i • ẋ  ∀ i ∈[κ]
		t, err := bf128.NewField().FromBytes(challengeResponse.T[i][:])
		if err != nil {
			return errs.WrapFailed(err, "cannot create field element")
		}
		x, err := bf128.NewField().FromBytes(challengeResponse.X[:])
		if err != nil {
			return errs.WrapFailed(err, "cannot create field element")
		}
		choice := uint64((s.receiverSeeds.Choices[i/8] >> (i % 8)) & 0b1)
		qiExpected := bf128.NewField().Select(choice, t, t.Add(x))
		isCorrect = isCorrect && qiExpected.Equal(qi)
	}
	if !isCorrect {
		return errs.NewIdentifiableAbort("R", "expected q != q in SoftspokenOT, consistency check failed")
	}
	return nil
}
