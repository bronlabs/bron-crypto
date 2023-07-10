// Copyright Copper.co; All Rights Reserved.
//
// Package softspoken implements of maliciously secure 1-out-of-2 Correlated
//  Oblivious Transfer extension (COTe) protocol. We follow the designs from
//  [SoftSpokenOT](https://eprint.iacr.org/2022/192), alongside a derandomization
//  from [MR19](https://eprint.iacr.org/2019/706). For the protocol description
//  we use the notation from ROT^{κ,l} from [KOS15](https://eprint.iacr.org/2015/546)
// (Figure 10).
//

// OBLIVIOUS TRANSFER (OT)
// At high level, a single 1-out-of-2 OT realizes this functionality:
//	┌------┐					  ┌------------------┐               ┌--------┐
//	|      |                      |                  |               |        |
//	|      |--> (Opt_0, Opt_1) -->|      1|2  OT     | <--(Choice)<--|        |
//	|Sender|                      |                  |               |Receiver|
//	|      | 					  └------------------┘               |		  |
//	|      |                               └-------> (DeltaOpt) -->  |		  |
//	└------┘							    						 └--------┘
//
// CORRELATED OBLIVIOUS TRANSFER (COT)
// In contrast, a single "Correlated" OT realizes tbe following functionality:
//	┌------┐					  ┌------------------┐               ┌--------┐
//	|      |                      |                  |               |        |
//	|      |----> (InputOpt) ---->|      1|2  COT    | <--(Choice)<--|        |
//	|Sender|                      |                  |               |Receiver|
//	|      | 					  └------------------┘               |		  |
//	|      | <----- (Correlation) <--------┴-------> (DeltaOpt) ---> |		  |
//	└------┘							    						 └--------┘
//  s.t. Correlation = Choice • DeltaOpt + InputOpt
//
// The Options, DeltaOpt and Correlation are elements of a group (e.g. Z_2,
// Z_{2^N}, F_q, elliptic curve points), whereas the choice is always a bit.
//
// OT EXTENSION (OTe, COTe)
// An "Extension" (both for OT and COT with Options of length κ) makes use of a
// PRG to expand each block of κ Base OTs  into L = n*κ OTs.

// ------------------------------ PROTOCOL F_COTe --------------------------- //
// PLAYERS: 2 parties, R (receiver) and S (sender).
//
// PARAMS:
// # κ (kappa), a computational security parameter. E.g. κ=256
// # L, a bit-level batch size. L=n*κ for  E.g. L=2*κ
// symbol for
// # σ (sigma), a statistical security parameter. L%σ=0. E.g. σ=128
//
// INPUTS:
// # R-> x ∈ [L]bits, the Choice bits.
// # S-> α ∈ [L]group, the InputOpt.
//
// OUTPUTS:
// # R-> z_B ∈ [L]group, the Correlation    s.t. z_B = x • α - z_A
// # S-> z_A ∈ [L]group, the DeltaOpt    	s.t. z_B = x • α - z_A
//
// PROTOCOL STEPS:
//
//	# A base OT protocol to generate random 1|2-OT results to be used as seeds:
//	  [κ × BaseOT]  (NOTE! The BaseOT roles are reversed w.r.t. the COTe roles)
//	  ├----> R: (k^i_0, k^i_1)                                            ∈ [2]×[κ]bits   ∀i∈[κ]
//	  └----> S: (Δ_i, k^i_{Δ_i})                                          ∈ 1 + [κ]bits   ∀i∈[κ]
//	# Seeding a PRG with the BaseOT Options to extend them:
//	  (Ext.1)   R: sample(x_i) ∈ [L']bits
//	  (Ext.2)   R: t^i_0, t^i_1 = PRG(k^i_0), PRG(k^i_1)                  ∈ [2]×[L']bits  ∀i∈[κ]
//	  .         S: t^i_{Δ_i}    = PRG(k^i_{Δ_i})                          ∈ [L']bits      ∀i∈[κ]
//	  (Ext.3)   R: u^i = t^i_0 ⊕ t^i_1 ⊕ x_i                              ∈ [L']bits      ∀i∈[κ]
//	  .            Send(u) => S                                           ∈ [L']×[κ]bits
//	  (Ext.4)   S: q^i = Δ_i • u^i + t^i_{Δ_i}                            ∈ [L']bits      ∀i∈[κ]
//	# A bit-level correlation used to check the extension consistency.
//	  (Check.1) S: sample(χ_i)                                            ∈ [σ]bits       ∀i∈[M]
//	  .            Send(χ) => R                                           ∈ [σ]×[M]bits
//	  (Check.2) R: x_val = x^hat_{m} + Σ{j=0}^{m-1} χ_j • x_hat_j       ∈ [σ]bits
//	  .                        └---where x^hat_j = x_{sj:s(j+1)}
//	  .            t^i_val = t^i_hat_{m} + Σ{j=0}^{m-1} χ_j • t^i_hat_j ∈ [σ]bits       ∀i∈[κ]
//	  .                        └---where t^i_hat_j = t^i_{sj:s(j+1)}
//	  .            Send(x_val, t^i_val) => S                          ∈ [σ] + [σ]×[κ]bits
//	  (Check.3) S: q^i_val = q^i_hat_{m} + Σ{j=0}^{m-1} χ_j • q^i_hat_j ∈ [σ]bits       ∀i∈[κ]
//	  .                        └---where q^i_hat_j = q^i_{sj:s(j+1)}
//	  .            ABORT if  q^i_val != t^i_val + Δ_i • x_val       ∈ [σ]bits       ∀i∈[κ]
//	# A bit-level randomization to destroy the bit-level correlation.
//	  (T&R.1)   R: transpose(t^i_0) ->t_j                                 ∈ [κ]bits       ∀j∈[L']
//	  .         S: transpose(q^i) -> q_j                                  ∈ [κ]bits       ∀j∈[L']
//	  (T&R.2)   R: v_x = Hash(j || t_j)                                   ∈ [κ]bits       ∀j∈[L]
//	  (T&R.3)   S: v_0 = Hash(j || q_j)                                   ∈ [κ]bits       ∀j∈[L]
//	  .         S: v_1 = Hash(j || (q_j + Δ) )                            ∈ [κ]bits       ∀j∈[L]
//	# A field-level correlation to obtain the final result (in the curve).
//	  (Derand.1) S: z_A_j = ECP(v_0_j)                                    ∈ curve.Scalar  ∀j∈[L]
//	  	  .             τ_j = ECP(v_1_j) - z_A_j + α_j                        ∈ curve.Scalar  ∀j∈[L]
//	  .                    └---where ECP(v) is the curve point obtained by mapping v to the curve
//	  .            Send(τ) => S                                           ∈ [L]curve.Scalar
//	  (Derand.2) R: z_B_j = τ_j - ECP(v_x_j)  if x_j == 1                 ∈ curve.Scalar  ∀j∈[L]
//	  .                   =     - ECP(v_x_j)  if x_j == 0
//
// ROUNDS (optimized):
//
//  0. Setup R & S:(...) ---(κ × BaseOT)---> (...)			[BaseOT]
//  1. R: (SessionId, x) ---(Round1)---> u					[Ext.1, Ext.2, Ext.3]
//  2. S: (SessionId, α) ---(Round2)---> (χ, τ, z_B) 		[Ext.2, Ext.4, Check.1, T&R.1, T&R.3, Derand.1]
//  3. R:         (χ, τ) ---(Round3)---> (x_val, t_val, z_A)[Check.2, T&R.1, T&R.2, Derand.2]
//  4. S: (x_val, t_val) ---(Round4)---> ()					[Check.3]
//
// -------------------------------------------------------------------------- //
package softspoken

import (
	"crypto/rand"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/ot/base/simplest"
)

// Round1Output contains the expanded and masked PRG outputs u_i
type Round1Output struct {
	u [Kappa][LPrimeBytes]byte // u_i ∈ [L']bits
}

// Round1Extend uses the PRG to extend the basseOT results.
func (receiver *Receiver) Round1Extend(
	uniqueSessionId [KappaBytes]byte, // Used to "salt" the PRG
	InputPackedChoices [LBytes]byte, // x_i ∈ [L]bits
) (round1Output *Round1Output, err error) {
	round1Output = &Round1Output{}

	// Copy uniqueSessionId into receiver
	copy(receiver.uniqueSessionId[:], uniqueSessionId[:])

	// (Ext.1) Store the input choices and fill the rest with random values
	copy(receiver.ExtPackChoices[:LBytes], InputPackedChoices[:])
	if _, err = rand.Read(receiver.ExtPackChoices[LBytes:]); err != nil {
		return nil, errs.WrapFailed(err, "sampling random bits for extended choice vector (Ext.1)")
	}

	// (Ext.2) Expand the baseOT results using them as seed to the PRG
	for i := 0; i < Kappa; i++ {
		for k := 0; k < KeyCount; k++ {
			// k^i_{Δ_i} --(PRG)--> t^i_{Δ_i}
			PRG(uniqueSessionId[:],
				receiver.baseOtSendOptions.OneTimePadEncryptionKeys[i][k][:],
				receiver.ExtOptions[k][i][:])
		}
	}
	// (Ext.3) Compute u_i and send it
	for i := 0; i < Kappa; i++ {
		for j := 0; j < LPrimeBytes; j++ {
			round1Output.u[i][j] = receiver.ExtOptions[0][i][j] ^ receiver.ExtOptions[1][i][j] ^ receiver.ExtPackChoices[j]
		}
	}
	return round1Output, nil
}

// Round2Output contains the random challenge for the consistency check.
type Round2Output struct {
	randomCheckMatrix [M][SigmaBytes]byte // χ_i ∈ [M]×[Sigma]uints
	derandomTau       [L]curves.Scalar    // m_i ∈ [L]curve.Scalar
}

// Round2Extend uses the PRG to extend the basseOT results. It also sends a
// challenge to the receiver in order to check the consistency.
func (sender *Sender) Round2Extend(
	uniqueSessionId [simplest.DigestSize]byte, // Used to "salt" the PRG
	Round1Output *Round1Output, // u_i ∈ [L']bits
	InputOpts [L]curves.Scalar, // α_i ∈ [L]curve.Scalar
) (round2Output *Round2Output, err error) {
	round2Output = &Round2Output{}
	round2Output.derandomTau = *new([L]curves.Scalar)

	// (Ext.2) Expand the baseOT results using them as seed to the PRG
	for i := 0; i < Kappa; i++ {
		// This is the core expansion of the OT: k^i_{Δ_i} --(PRG)--> t^i_{Δ_i}
		PRG(uniqueSessionId[:],
			sender.baseOtRecOutputs.OneTimePadDecryptionKey[i][:],
			sender.ExtChosenOpt[i][:])
	}

	// (Ext.4) Compute q_i (constant time)
	for i := 0; i < Kappa; i++ {
		// q_i = Δ_i • u_i + t_i
		for j := 0; j < LPrimeBytes; j++ {
			qiTemp := Round1Output.u[i][j] ^ sender.ExtChosenOpt[i][j]
			if sender.baseOtRecOutputs.RandomChoiceBits[i] != 0 {
				sender.ExtCorrelations[i][j] = qiTemp
			} else {
				sender.ExtCorrelations[i][j] = sender.ExtChosenOpt[i][j]
			}
		}
	}

	// (Check.1) Sample and send chi_i as challenge to check consistency
	for i := 0; i < M; i++ {
		if _, err := rand.Read(round2Output.randomCheckMatrix[i][:]); err != nil {
			return nil, errs.WrapFailed(err, "sampling random bits for challenge Chi (Check.1)")
		}
	}

	// (T&R.1) Transpose q^i -> q_j and q^i+Δ -> q_j+Δ
	q_j := transposeBooleanMatrix(sender.ExtCorrelations)
	var q_j_plusDelta [L][KappaBytes]byte
	copy(q_j_plusDelta[:], q_j[:L])
	for i := 0; i < KappaBytes; i++ {
		Delta := sender.baseOtRecOutputs.PackedRandomChoiceBits[i]
		for j := 0; j < L; j++ {
			q_j_plusDelta[j][i] ^= Delta
		}
	}

	// (T&R.3) Randomize by hashing the first L rows of q_j and q_j+Δ (throwing away the rest)
	v_0, err := HashSalted(uniqueSessionId[:], q_j[:L])
	if err != nil {
		return nil, errs.WrapFailed(err, "bad hashing q_j for SoftSpoken COTe (T&R.3)")
	}
	v_1, err := HashSalted(uniqueSessionId[:], q_j_plusDelta[:])
	if err != nil {
		return nil, errs.WrapFailed(err, "bad hashing q_j_pDelta for SoftSpoken COTe (T&R.3)")
	}

	// (Derand.1) Derandomize (z_A) by mapping to curve points and creating the correlation
	for j := 0; j < L; j++ {
		// z_A_j = ECP(v_0_j)
		sender.OutDeltaOpt[j], err = sender.curve.Scalar.SetBytes(v_0[j][:])
		if err != nil {
			return nil, errs.WrapFailed(err, "bad v_0 mapping to curve elements (Derand.1)")
		}
		// τ_j = ECP(v_1_j) - z_A_j + α_j
		round2Output.derandomTau[j], err = sender.curve.Scalar.SetBytes(v_1[j][:])
		if err != nil {
			return nil, errs.WrapFailed(err, "bad v_1 mapping to curve elements (Derand.1)")
		}
		round2Output.derandomTau[j] = round2Output.derandomTau[j].Sub(sender.OutDeltaOpt[j]).Add(InputOpts[j])
	}
	return round2Output, nil
}

// Round2Output this is Alice's response to Bob in COTe
type Round3Output struct {
	x_val [SigmaBytes]byte        // plain x in the protocol
	t_val [Kappa][SigmaBytes]byte // plain t^i in the protocol
}

// Round3ProveConsistency answers to the challenge of S.
func (receiver *Receiver) Round3ProveConsistency(round2Out *Round2Output) (round3Output *Round3Output, err error) {
	round3Output = &Round3Output{}

	// (Check.2) Compute the challenge response x, t^i \forall i \in [kappa]
	// 		x = x^hat_{m+1} ...
	copy(round3Output.x_val[:], receiver.ExtPackChoices[LBytes:LBytes+SigmaBytes])
	// 		                ... + Σ{j=0}^{m-1} χ_j • x_hat_j
	for j := 0; j < M; j++ {
		x_hat_j := receiver.ExtPackChoices[j*SigmaBytes : (j+1)*SigmaBytes]
		Chi_j := round2Out.randomCheckMatrix[j][:]
		for k := 0; k < SigmaBytes; k++ {
			round3Output.x_val[k] ^= (Chi_j[k] & x_hat_j[k])
		}
	}
	// 		t^i = ...
	for i := 0; i < Kappa; i++ {
		//         ... t^i_hat_{m+1} ...
		copy(round3Output.t_val[i][:], receiver.ExtOptions[0][i][LBytes:LBytes+SigmaBytes])
		//                           ... + Σ{j=0}^{m-1} χ_j • t^i_hat_j
		for j := 0; j < M; j++ {
			t_hat_j := receiver.ExtOptions[0][i][j*SigmaBytes : (j+1)*SigmaBytes]
			Chi_j := round2Out.randomCheckMatrix[j][:]
			for k := 0; k < SigmaBytes; k++ {
				round3Output.t_val[i][k] ^= (Chi_j[k] & t_hat_j[k])
			}
		}
	}

	// (T&R.1) Transpose t^i_0 into t_j
	t_j := transposeBooleanMatrix(receiver.ExtOptions[0]) // t_j ∈ [L'][κ]bits

	// (T&R.2) Hash L rows of t_j using the index as salt.
	v_x, err := HashSalted(receiver.uniqueSessionId[:], t_j[:])
	if err != nil {
		return nil, errs.WrapFailed(err, "bad hashing t_j for SoftSpoken COTe (T&R.2)")
	}

	// (Derand.2) Derandomize  and Correlate in the curve (constant time)
	var v_x_NegCurve, v_x_curve_corr curves.Scalar
	for j := 0; j < L; j++ {
		// ECP(v_x_j)
		v_x_NegCurve, err = receiver.curve.Scalar.SetBytes(v_x[j][:])
		if err != nil {
			return nil, errs.WrapFailed(err, "bad v_x mapping to curve elements (Derand.1)")
		}
		v_x_NegCurve = v_x_NegCurve.Neg()
		v_x_curve_corr = round2Out.derandomTau[j].Add(v_x_NegCurve)
		if UnpackBit(j, receiver.ExtPackChoices[:]) != 0 {
			// z_B_j = τ_j - ECP(v_x_j)  if x_j == 1
			receiver.OutCorrelations[j] = v_x_curve_corr
		} else {
			//       =     - ECP(v_x_j)  if x_j == 0
			receiver.OutCorrelations[j] = v_x_NegCurve
		}
	}
	return round3Output, nil
}

// Round4CheckConsistency checks the consistency using the challenge response.
func (sender *Sender) Round4CheckConsistency(round2Out *Round2Output, round3Output *Round3Output) error {
	// (Check.3) Check the consistency of the challenge response computing q^i
	qi_val := [SigmaBytes]byte{}
	var q_expected, qi_sum byte
	for i := 0; i < Kappa; i++ {
		// q^i = q^i_hat_{m+1} ...
		copy(qi_val[:], sender.ExtCorrelations[i][LBytes:LBytes+SigmaBytes])
		//                     ... + Σ{j=0}^{m-1} χ_j • q^i_hat_j
		for j := 0; j < M; j++ {
			qi_hat_j := sender.ExtCorrelations[i][j*SigmaBytes : (j+1)*SigmaBytes]
			Chi_j := round2Out.randomCheckMatrix[j][:]
			for k := 0; k < SigmaBytes; k++ {
				qi_val[k] ^= (qi_hat_j[k] & Chi_j[k])
			}
		}
		//  and ABORT if q^i != t^i + Δ_i • x   ∀ i ∈[κ]
		for k := 0; k < SigmaBytes; k++ {
			qi_sum = round3Output.t_val[i][k] ^ round3Output.x_val[k]
			if sender.baseOtRecOutputs.RandomChoiceBits[i] != 0 {
				q_expected = qi_sum
			} else {
				q_expected = round3Output.t_val[i][k]
			}
			if !(q_expected == qi_val[k]) {
				return errs.NewIdentifiableAbort("q_val != q_expected in SoftspokenOT")
			}
		}
	}
	return nil
}
