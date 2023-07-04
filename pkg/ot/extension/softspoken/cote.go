// Copyright Copper.co; All Rights Reserved.
//
// Package softspoken implements of maliciously secure 1-out-of-2 Correlated
// Oblivious Transfer extension (COTe) protocol. We follow most of ROT^{κ,l} from
// [KOS15](https://eprint.iacr.org/2015/546) (Figure 10), based on the designs
// from [SoftSpokenOT](https://eprint.iacr.org/2022/192).
//

// At high level, a 1-out-of-2 OT realizes this functionality:
//	┌------┐					  ┌------------------┐               ┌--------┐
//	|      |                      |                  |               |        |
//	|      |--> (Opt_0, Opt_1) -->|      1|2  OT     | <--(Choice)<--|        |
//	|Sender|                      |                  |               |Receiver|
//	|      | 					  └------------------┘               |		  |
//	|      |                               └-------> (DeltaOpt) -->  |		  |
//	└------┘							    						 └--------┘
// In contrast, for "Correlated" OTs, we get:
//	┌------┐					  ┌------------------┐               ┌--------┐
//	|      |                      |                  |               |        |
//	|      |----> (InputOpt) ---->|      1|2  COT    | <--(Choice)<--|        |
//	|Sender|                      |                  |               |Receiver|
//	|      | 					  └------------------┘               |		  |
//	|      | <----- (Correlation) <--------┴-------> (DeltaOpt) ---> |		  |
//	└------┘							    						 └--------┘
//  s.t. Correlation = Choice • DeltaOpt + InputOption
//
// The Options, DeltaOpt and Correlation are elements of a group (e.g. Z_2,
// Z_{2^N}, F_q, elliptic curve points), whereas the choice is always a bit.
//
//

// ----------------------------- Protocol F_COTe ---------------------------- //
// PLAYERS: 2 parties, R (receiver) and S (sender).
//
// PARAMS:
// # κ (kappa), a computational security parameter. E.g. κ=256
// # L, a bit-level batch size. E.g. L=κ
// # s, a statistical security parameter. L%s=0. E.g. s=128 (Uint128)
//
// INPUTS:
// # R-> x ∈ [L]bits, the Choice bits.
// # S-> α ∈ [L]group, the InputOpt.
//
// OUTPUTS:
// # R-> γ ∈ [L]group, the DeltaOpt     s.t. γ = x • α + β
// # S-> β ∈ [L]group, the Correlation  s.t. γ = x • α + β
//
// STEPS:
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
//	  (Check.1) S: sample(χ_i)                                            ∈ [s]bits       ∀i∈[m]
//	  .            Send(χ) => R                                           ∈ [s]×[m]bits
//	  (Check.2) R: x_check = x^hat_{m} + Σ{j=0}^{m-1} χ_j • x_hat_j       ∈ [2^s]
//	  .                        └---where x^hat_j = x_{sj:s(j+1)}
//	  .            t^i_check = t^i_hat_{m} + Σ{j=0}^{m-1} χ_j • t^i_hat_j ∈ [2^s]         ∀i∈[κ]
//	  .                        └---where t^i_hat_j = t^i_{sj:s(j+1)}
//	  .            Send(x_check, t^i_check) => S                          ∈ [s] + [s]×[κ]bits
//	  (Check.3) S: q^i_check = q^i_hat_{m} + Σ{j=0}^{m-1} χ_j • q^i_hat_j ∈ [2^s]         ∀i∈[κ]
//	  .                        └---where q^i_hat_j = q^i_{sj:s(j+1)}
//	  .            ABORT if  q^i_check != t^i_check + Δ_i • x_check       ∈ [2^s]         ∀i∈[κ]
//	# A bit-level randomization to destroy the bit-level correlation.
//	  (T&R.1)   R: transpose(t^i_0) ->t_j                                 ∈ [κ]bits       ∀j∈[L']
//	  .         S: transpose(q^i) -> q_j                                  ∈ [κ]bits       ∀j∈[L']
//	  (T&R.2)   R: v_x = Hash(j || t_j)                                   ∈ [κ]bits       ∀j∈[L]
//	  .         S: v_0 = Hash(j || q_j)                                   ∈ [κ]bits       ∀j∈[L]
//	  .         S: v_1 = Hash(j || (q_j + Δ) )                            ∈ [κ]bits       ∀j∈[L]
//	# A field-level correlation to obtain the final result (in the curve).
//	  (Derand.1) R: τ_j = ECP(v_0_j) - ECP(v_1_j) + α_j                   ∈ curve.Scalar  ∀j∈[L]
//	  .                    └---where ECP(v) is the curve point obtained by mapping v to the curve
//	  .            Send(τ) => S                                           ∈ [L]curve.Scalar
package softspoken

import (
	"crypto/rand"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	uint128 "github.com/copperexchange/crypto-primitives-go/pkg/core/modular"
	"github.com/copperexchange/crypto-primitives-go/pkg/ot/base/simplest"
	"golang.org/x/crypto/sha3"
)

// TODO: Testing
// TODO: Finish pseudocode above.
// TODO: refactor to use hash module
//      -> Code hash function using AES primitives and use it for H
// TODO: refactor to have a secure rand module in core

const (
	// ------------------------ CONFIGURABLE PARAMETERS --------------------- //
	// Kappa (κ) is the computational security parameter (a.k.a. λ in SoftSpokenOT)
	Kappa = 256

	// L is the batch size used in the cOT functionality.
	L = 256

	// s is the statistical security parameter. Must divide L (L%s=0) for SoftSpokenOT.
	//  This defines the data type of the consistency check to 2^s bits (e.g. s=128 -> Uint128)
	s = 128

	// ---------------------- NON-CONFIGURABLE PARAMETERS ------------------- //
	// KeyCount is the number of scalars to choose from in the BaseOT, as well as
	//  the number of shares _per_ choice of the cOT. Set to 2 for 1-out-of-2 OT
	//  and one share per party.
	KeyCount = 2

	// length of pseudorandom seed expansion
	LPrime = L + s

	// number of blocks in the consistency check
	m = L / s

	// Equivalents in Bytes
	KappaBytes  = Kappa >> 3
	LBytes      = L >> 3
	sBytes      = s >> 3
	LPrimeBytes = LPrime >> 3
	mBytes      = m >> 3
)

type Receiver struct {
	// baseOtSendOptions (k^i_0, k^i_1) ∈ [2][κ][κ]bits are the options used while
	//  of playing the sender in a base OT protocol. They are inputs to COTe.
	baseOtSendOptions *simplest.SenderOutput

	// ExtPackChoices (x_i) ∈ [L']bits are the choice bits for the OTe.
	ExtPackChoices [LPrimeBytes]byte

	// ExpOptions (t^i) ∈ [2][κ][L']bits are expansions of BaseOT results using a PRG.
	ExpOptions [KeyCount][Kappa][LPrimeBytes]byte

	// OutCorrelations (m_x) ∈ [L]curve.Scalar are the output "correlations" (in the curve).
	OutCorrelations [L]curves.Scalar

	curve           *curves.Curve
	uniqueSessionId [simplest.DigestSize]byte // store this between rounds
}

type Sender struct {
	// baseOtRecOutputs (Δ_i ∈ [κ]bits, k^i_{Δ_i} ∈ [κ][κ]bits) are the results
	// of playing the receiver in a base OT protocol. They are inputs of COTe.
	baseOtRecOutputs *simplest.ReceiverOutput

	// ExtChosenOpt (t^i_{Δ_i}) are the expansion the base OT chosen option using a PRG
	ExtChosenOpt [Kappa][LPrimeBytes]byte

	// ExtCorrelations (q_i) ∈ [κ][L']bits are the extended correlations, such that:
	//    q^i = Δ_i • x + t^i
	ExtCorrelations [Kappa][LPrimeBytes]byte

	// OutBaseChoices (Δ_i)∈ [κ]bits are the choice bits from the base OTs.
	OutBaseChoices *[]int

	// OutChosenOpt (m_i) ∈ [L]curve.Scalar are the output "ChosenOpt" group elements.
	OutChosenOpt [L]curves.Scalar

	// curve is the elliptic curve used in the protocol.
	curve *curves.Curve
}

// NewCOtReceiver creates a `Receiver` instance for the SoftSpokenOT protocol.
// The `baseOtResults` are the results of playing the sender role in kappa baseOTs.
func NewCOtReceiver(baseOtResults *simplest.SenderOutput, curve *curves.Curve) *Receiver {
	return &Receiver{
		baseOtSendOptions: baseOtResults,
		curve:             curve,
	}
}

// NewCOtSender creates a `Sender` instance for the SoftSpokenOT protocol.
// The `baseOtResults` are the results of playing the receiver role in kappa baseOTs.
func NewCOtSender(baseOtResults *simplest.ReceiverOutput, curve *curves.Curve) *Sender {
	return &Sender{
		baseOtRecOutputs: baseOtResults,
		OutBaseChoices:   &baseOtResults.RandomChoiceBits,
		curve:            curve,
	}
}

// Round1Output contains the expanded and masked PRG outputs u_i
type Round1Output struct {
	u [Kappa][LPrimeBytes]byte
}

// Round1Extend uses the PRG to extend the basseOT results.
func (receiver *Receiver) Round1Extend(
	uniqueSessionId [KappaBytes]byte, // Used to "salt" the PRG
	InputPackedChoices [LBytes]byte, // x_i ∈ [L]bits
) (round1Output *Round1Output, err error) {

	// Copy uniqueSessionId into receiver
	copy(receiver.uniqueSessionId[:], uniqueSessionId[:])

	// (Ext.1) Store the input choices and fill the rest with random values
	copy(receiver.ExtPackChoices[:LBytes], InputPackedChoices[:])
	if _, err = rand.Read(receiver.ExtPackChoices[LBytes:]); err != nil {
		return nil, errs.WrapFailed(err, "sampling random bits for extended choice vector (Ext.1)")
	}

	// (Ext.2) Expand the baseOT results using them as seed to the PRG
	// expandedOtResults are the results of expanding the base OT results using a PRG.
	for i := 0; i < Kappa; i++ {
		for j := 0; j < KeyCount; j++ {
			shake := sha3.NewCShake256(uniqueSessionId[:], []byte("Copper_Softspoken_COTe"))
			if _, err = shake.Write(receiver.baseOtSendOptions.OneTimePadEncryptionKeys[i][j][:]); err != nil {
				return nil, errs.WrapFailed(err, "writing seed OT into shake in SoftSpoken COTe (Ext.2)")
			}
			// This is the core pseudorandom expansion of the secret OT input seeds k_i^0 and k_i^1
			// use the uniqueSessionId as the "domain separator", and the _secret_ seed as the input
			if _, err = shake.Read(receiver.ExpOptions[j][i][:]); err != nil {
				return nil, errs.WrapFailed(err, "reading from shake in SoftSpoken COTe (Ext.2)")
			}
		}
	}

	// (Ext.3) Compute u_i and send it
	for i := 0; i < Kappa; i++ {
		for j := 0; j < LPrimeBytes; j++ {
			round1Output.u[i][j] = receiver.ExpOptions[0][i][j] ^ receiver.ExpOptions[1][i][j] ^ receiver.ExtPackChoices[j]
		}
	}
	return round1Output, nil
}

// Round2Output contains the random challenge for the consistency check.
type Round2Output struct {
	randomCheckMatrix [m + 1][sBytes]byte // χ_i ∈ [L']bits
	derandTau         [L]curves.Scalar    // m_i ∈ [L]curve.Scalar
}

// Round2Extend uses the PRG to extend the basseOT results. It also sends a
// challenge to the receiver in order to check the consistency.
func (sender *Sender) Round2Extend(
	uniqueSessionId [simplest.DigestSize]byte, // Used to "salt" the PRG
	Round1Output *Round1Output, // u_i ∈ [L']bits
	InputDeltaOpts [L]curves.Scalar, // α_i ∈ [L]curve.Scalar
) (round2Output *Round2Output, err error) {

	// (Ext.2) Expand the baseOT results using them as seed to the PRG
	for i := 0; i < Kappa; i++ {
		shake := sha3.NewCShake256(uniqueSessionId[:], []byte("Copper_Softspoken_COTe"))
		if _, err := shake.Write(sender.baseOtRecOutputs.OneTimePadDecryptionKey[i][:]); err != nil {
			return nil, errs.WrapFailed(err, "writing seed OT into shake in SoftSpoken COTe (Ext.2)")
		}
		// This is the core pseudorandom expansion of the secret OT input seeds k_i^0 and k_i^1
		// use the uniqueSessionId as the "domain separator", and the _secret_ seed as the input
		if _, err := shake.Read(sender.ExtChosenOpt[i][:]); err != nil {
			return nil, errs.WrapFailed(err, "reading from shake in COTe (Ext.2)")
		}
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
	for i := 0; i < m+1; i++ {
		if _, err := rand.Read(round2Output.randomCheckMatrix[i][:]); err != nil {
			return nil, errs.WrapFailed(err, "sampling random bits for challenge chi (Check.1)")
		}
	}

	// (T&R.1) Transpose q^i -> q_j and q^i+Δ -> q_j+Δ
	q_j := transposeBooleanMatrix(sender.ExtCorrelations)
	var q_j_pDelta [LPrime][KappaBytes]byte
	copy(q_j_pDelta[:], q_j[:])
	for i := 0; i < Kappa; i++ {
		for j := 0; j < LPrimeBytes; j++ {
			q_j_pDelta[j][i] ^= sender.baseOtRecOutputs.PackedRandomChoiceBits[i]
		}
	}

	// (T&R.3) Randomize by hashing the first L rows of q_j and q_j+Δ (throwing away the rest)
	v_0, err := HashSalted(uniqueSessionId[:], q_j[:])
	if err != nil {
		return nil, errs.WrapFailed(err, "bad hashing q_j for SoftSpoken COTe (T&R.3)")
	}
	v_1, err := HashSalted(uniqueSessionId[:], q_j_pDelta[:])
	if err != nil {
		return nil, errs.WrapFailed(err, "bad hashing q_j_pDelta for SoftSpoken COTe (T&R.3)")
	}

	// (Derand.1) Derandomize by mapping to curve points and create the correlation
	for j := 0; j < L; j++ {
		sender.OutChosenOpt[j], err = sender.curve.Scalar.SetBytes(v_0[j][:])
		if err != nil {
			return nil, errs.WrapFailed(err, "bad v_0 mapping to curve elements (Derand.1)")
		}
		round2Output.derandTau[j], err = sender.curve.Scalar.SetBytes(v_1[j][:])
		if err != nil {
			return nil, errs.WrapFailed(err, "bad v_1 mapping to curve elements (Derand.1)")
		}
		round2Output.derandTau[j] = round2Output.derandTau[j].Sub(sender.OutChosenOpt[j]).Add(InputDeltaOpts[j])
	}
	return round2Output, nil
}

// Round2Output this is Alice's response to Bob in COTe
type Round3Output struct {
	x_check uint128.Uint128        // plain x in the protocol
	t_check [Kappa]uint128.Uint128 // plain t^i in the protocol
}

// Round3ProveConsistency answers to the challenge of S.
func (receiver *Receiver) Round3ProveConsistency(round2Out *Round2Output) (round3Output *Round3Output, err error) {

	// (Check.2) Compute the challenge response x, t^i \forall i \in [kappa]
	// 		x = x^hat_{m+1} ...
	round3Output.x_check = uint128.FromBytes(receiver.ExtPackChoices[LBytes : LBytes+sBytes])
	// 		                ... + Σ{j=0}^{m-1} χ_j • x_hat_j
	for j := 0; j < m; j++ {
		x_hat_j := uint128.FromBytes(receiver.ExtPackChoices[j*sBytes : (j+1)*sBytes])
		Chi_j := uint128.FromBytes(round2Out.randomCheckMatrix[j][j*sBytes : (j+1)*sBytes])
		round3Output.x_check = round3Output.x_check.AddWrap(Chi_j.MulWrap(x_hat_j))
	}
	// 		t^i = ...
	for i := 0; i < Kappa; i++ {
		//         ... t^i_hat_{m+1} ...
		round3Output.t_check[i] = uint128.FromBytes(receiver.ExpOptions[0][i][LBytes : LBytes+sBytes])
		//                           ... + Σ{j=0}^{m-1} χ_j • t^i_hat_j
		for j := 0; j < m; j++ {
			t_hat_j := uint128.FromBytes(receiver.ExpOptions[0][i][j*sBytes : (j+1)*sBytes])
			Chi_j := uint128.FromBytes(round2Out.randomCheckMatrix[j][j*sBytes : (j+1)*sBytes])
			round3Output.t_check[i] = round3Output.t_check[i].AddWrap(Chi_j.MulWrap(t_hat_j))
		}
	}

	// (T&R.1) Transpose t^i_0 into t_j
	t_j := transposeBooleanMatrix(receiver.ExpOptions[0]) // t_j ∈ [L'][κ]bits

	// (T&R.2) Hash L rows of t_j using the index as salt.
	v_x, err := HashSalted(receiver.uniqueSessionId[:], t_j[:])
	if err != nil {
		return nil, errs.WrapFailed(err, "bad hashing t_j for SoftSpoken COTe (T&R.2)")
	}

	// (Derand.2) Derandomize and Correlate in the curve
	var v_x_curve, v_x_curve_corr curves.Scalar
	for j := 0; j < L; j++ {
		v_x_curve, err = receiver.curve.Scalar.SetBytes(v_x[j][:])
		if err != nil {
			return nil, errs.WrapFailed(err, "bad v_x mapping to curve elements (Derand.1)")
		}
		v_x_curve_corr = round2Out.derandTau[j].Sub(v_x_curve)
		if UnpackBit(j, receiver.ExtPackChoices[:]) {
			receiver.OutCorrelations[j] = v_x_curve_corr
		} else {
			receiver.OutCorrelations[j] = v_x_curve
		}
	}
	return round3Output, nil
}

// Round4CheckConsistency checks the consistency using the challenge response.
func (sender *Sender) Round4CheckConsistency(round2Out *Round2Output, round3Output *Round3Output) error {
	// (Check.3) Check the consistency of the challenge response computing q^i
	for i := 0; i < Kappa; i++ {
		// q^i = q^i_hat_{m+1} ...
		q_check := uint128.FromBytes(sender.ExtCorrelations[i][LBytes : LBytes+sBytes])
		//                     ... + Σ{j=0}^{m-1} χ_j • q^i_hat_j
		for j := 0; j < m; j++ {
			q_hat_j := uint128.FromBytes(sender.ExtCorrelations[i][j*sBytes : (j+1)*sBytes])
			Chi_j := uint128.FromBytes(round2Out.randomCheckMatrix[j][j*sBytes : (j+1)*sBytes])
			q_check = q_check.AddWrap(Chi_j.MulWrap(q_hat_j))
		}
		//  and ABORT if q^i != t^i + Δ_i • x   ∀ i ∈[κ]
		var q_expected uint128.Uint128
		q_sum := round3Output.t_check[i].AddWrap(round3Output.x_check)
		if sender.baseOtRecOutputs.RandomChoiceBits[i] != 0 {
			q_expected = q_sum
		} else {
			q_expected = round3Output.t_check[i]
		}
		if !q_check.SubWrap(q_expected).IsZero() {
			return errs.NewIdentifiableAbort("q_check != q_expected")
		}
	}
	return nil
}
