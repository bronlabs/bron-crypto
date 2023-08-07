// Package softspoken implements of maliciously secure 1-out-of-2 Correlated
//
// Oblivious Transfer extension (COTe) protocol. We follow the designs from:
// - [SoftSpokenOT](https://eprint.iacr.org/2022/192) for the OT extension
// - [MR19](https://eprint.iacr.org/2019/706) for the Derandomization ("Correlated")
// We use the notation from ROT^{κ,l} from [KOS15](https://eprint.iacr.org/2015/546)
// for the protocol description (Figure 10). We apply the "Fiat-Shamir" heuristic,
// substituting the coin tossing required for the consistency check with the
// hash of the public transcript (using an (*) to denote the changes). We also
// apply the "Forced Reuse" technique from [DKLs23](https://eprint.iacr.org/2023/765)
// fixing one single batch of input choice bits (l_OTe=1) and reusing that batch
// for all of the input batches.
//
// ============================= FUNCTIONALITIES ============================ //
//
// OBLIVIOUS TRANSFER (OT)
// At high level, a single 1-out-of-2 OT realises this functionality:
//
//	┌------┐                      ┌------------------┐               ┌--------┐
//	|      |                      |                  |               |        |
//	|      |--> (Opt_0, Opt_1) -->|      1|2  OT     | <--(Choice)<--|        |
//	|Sender|                      |                  |               |Receiver|
//	|      |                      └------------------┘               |        |
//	|      |                               └-------> (DeltaOpt) -->  |        |
//	└------┘                                                         └--------┘
//
// s.t. DeltaOpt = Opt_{Choice} = Opt_0 • (1-Choice) + Opt_1 • Choice
//
// CORRELATED OBLIVIOUS TRANSFER (COT)
// In contrast, a single "Correlated" OT realises tbe following functionality:
//
//	┌------┐                      ┌------------------┐               ┌--------┐
//	|      |                      |                  |               |        |
//	|      |----> (InputOpt) ---->|      1|2  COT    | <--(Choice)<--|        |
//	|Sender|                      |                  |               |Receiver|
//	|      |                      └------------------┘               |        |
//	|      | <----- (Correlation) <--------┴-------> (DeltaOpt) ---> |        |
//	└------┘                                                         └--------┘
//	s.t. Correlation = Choice • InputOpt - DeltaOpt
//
// The Options, DeltaOpt and Correlation are elements of a group (e.g. Z_2,
// Z_{2^N}, F_q, elliptic curve points), whereas Choice is always a bit.
//
// OT EXTENSION (OTe, COTe)
// An "Extension" (both for OT and COT with Options of length κ) makes use of a
// PRG to expand each block of κ Base OTs  into L = n*κ OTs.
//
// ========================== PROTOCOL STEPS F_COTe ========================= //
// PLAYERS: 2 parties, R (receiver) and S (sender).
//
// PARAMS:
// # κ (kappa), a computational security parameter. E.g. κ=256
// # ξ, a bit-level batch size. ξ=L_ote*(κ+...) for a chosen L_ote ∈ ℕ. ξ'=ξ+σ. L_ote=1 for "Forced Reuse" (DKLS23). ξ=κ+2s for DKLS23.
// # σ (sigma), a statistical security parameter. ξ%σ=0. E.g. σ=128
// # ω (omega), a field-level expansion batch size. ω=2 for DKLS23 2PCmult.
// # L, the number of reuses of the output OTe batch. L>1 only for "Forced Reuse" (as in DKLS23).
//
// INPUTS:
// # R-> x ∈ [ξ] bits, the Choice bits.
// # S-> α ∈ [L][ω][ξ]curve.Scalar, the InputOpt.
//
// OUTPUTS:
// # R-> z_B ∈ [L][ω][ξ]group, the Correlation    s.t. z_A = x • α - z_B
// # S-> z_A ∈ [L][ω][ξ]group, the DeltaOpt       s.t. z_A = x • α - z_B
//
// PROTOCOL STEPS:
//
//	# A base OT protocol to generate random 1|2-OT results to be used as seeds:
//	  [κ × BaseOT]  (NOTE! The BaseOT roles are reversed w.r.t. the OTe roles)
//	  ├---->R: (k^i_0, k^i_1)                                         ∈ [2]×[κ]bits   ∀i∈[κ]
//	  └---->S: (Δ_i, k^i_{Δ_i})                                       ∈ 1 + [κ]bits   ∀i∈[κ]
//	# Seeding a PRG with the BaseOT Options to extend them:
//	  (Ext.1)   R: sample(x_i), ∈ [ξ'-ξ]bits, append to x ∈ [ξ']bits  ∈ [ξ']bits
//	  (Ext.2)   R: t^i_0, t^i_1 = PRG(k^i_0), PRG(k^i_1)              ∈ [2]×[ξ']bits  ∀i∈[κ]
//	  .         S: t^i_{Δ_i}    = PRG(k^i_{Δ_i})                      ∈ [ξ']bits      ∀i∈[κ]
//	  (Ext.3)   R: u^i = t^i_0 ⊕ t^i_1 ⊕ x_i                          ∈ [ξ']bits      ∀i∈[κ]
//	  .            Send(u) => S                                       ∈ [ξ']×[κ]bits
//	  (Ext.4)   S: q^i = Δ_i • u^i + t^i_{Δ_i}                        ∈ [ξ']bits      ∀i∈[κ]
//	# A bit-level correlation used to check the extension consistency.
//	  (Check.1) S: sample(χ_i) ((*) from transcript in Fiat-Shamir)   ∈ [σ]bits       ∀i∈[M]
//	  .            Send(χ) => R                                       ∈ [σ][M]bits
//	  (Check.2) R: ẋ = x̂_{m+1} + Σ{j=1}^{m} χ_j • x_hat_j             ∈ [σ]bits
//	  .                        └---where x̂_j = x_{σj:σ(j+1)}
//	  .            ṫ^i = t^i_hat_{m+1} + Σ{j=1}^{m} χ_j•t^i_hat_j     ∈ [σ]bits       ∀i∈[κ]
//	  .                        └---where t^i_hat_j = t^i_{σj:σ(j+1)}
//	  .            Send(ẋ, ṫ^i) => S                                  ∈ [σ] + [κ]×[σ]bits
//	  (Check.3) S: q̇^i = q^i_hat_{m} + Σ{j=0}^{m-1} χ_j•q^i_hat_j     ∈ [σ]bits       ∀i∈[κ]
//	  .                        └---where q^i_hat_j = q^i_{σj:σ(j+1)}
//	  .            ABORT if  q̇^i != ṫ^i + Δ_i • ẋ                     ∈ [σ]bits       ∀i∈[κ]
//	# A bit-level randomization to destroy the bit-level correlation.
//	  (T&R.1)   R: transpose(t^i_0) ->t_j                             ∈ [κ]bits       ∀j∈[ξ']
//	  .         S: transpose(q^i) -> q_j                              ∈ [κ]bits       ∀j∈[ξ']
//	  (T&R.2)   R: v_x = Hash(j || t_j)                               ∈ [ω]×[κ]bits   ∀j∈[ξ]
//	  (T&R.3)   S: v_0 = Hash(j || q_j)                               ∈ [ω]×[κ]bits   ∀j∈[ξ]
//	  .         S: v_1 = Hash(j || (q_j + Δ))                         ∈ [ω]×[κ]bits   ∀j∈[ξ]
//	# A field-level correlation to obtain the COTe result.
//	  (Derand.1) S: z_A_j = ECP(v_0_j)                                ∈ curve.Scalar  ∀j∈[ξ] ∀k∈[ω] ∀[L]
//	  .             τ_j = ECP(v_1_j) - z_A_j + α_j                    ∈ curve.Scalar  ∀j∈[ξ] ∀k∈[ω] ∀[L]
//	  .                    └---where ECP(v) is the mapping of v to the curve
//	  .            Send(τ) => R                                       ∈ [L][ω][ξ]curve.Scalar
//	  (Derand.2) R: z_B_j = τ_j - ECP(v_x_j)  if x_j == 1             ∈ curve.Scalar  ∀j∈[ξ] ∀k∈[ω] ∀[L]
//	  .                   =     - ECP(v_x_j)  if x_j == 0
//
// ============================ PROTOCOL ROUNDS ============================= //
// Rounds end
// -------------------------------------------------------------------------- //
// ROUNDS (COTe):
//
//  0. Setup R & S:(...) ---(κ × BaseOT)--->(...) [BaseOT]
//  1. R: (x)------(Round1)--->(u,v_x)            [Ext.1, Ext.2, Ext.3]
//  2. S: (α)------(Round2)--->(χ,τ,z_B)          [Ext.2, Ext.4, Check.1, T&R.1, T&R.3, Derand.1]
//  3. R: (χ,τ)----(Round3)--->(ẋ,ṫ,z_A)          [Check.2, T&R.1, T&R.2, Derand.2]
//  4. S: (ẋ,ṫ)----(Round4)--->()                 [Check.3]
//
// -------------------------------------------------------------------------- //
// ROUNDS (COTe with fiat-shamir (*)):
//
//  0. Setup R & S:(...) ---(κ × BaseOT)--->(...) [BaseOT]
//  1. R: (x)---------(Round1)--->(u,ẋ,ṫ)         [Ext.1, Ext.2, Ext.3, Check.1*, Check.2, T&R.1, T&R.2]
//  2. S: (u,ẋ,ṫ,α)---(Round2)--->(τ,z_B)         [Ext.1, Ext.2, Ext.4, T&R.1, T&R.3, Derand.1, Check.1*, Check.3]
//  3. R: (τ)---------(Round3)--->(z_A)           [Derand.2]
//
// -------------------------------------------------------------------------- //
// ROUNDS (OTe):
//
//  0. Setup R & S:(...) ---(κ × BaseOT)--->(...) [BaseOT]
//  1. R: (x) -----(Round1)--->(u, v_x)           [Ext.1, Ext.2, Ext.3]
//  2. S: (u) -----(Round2)--->(χ, v_0, v_1)      [Ext.2, Ext.4, Check.1, T&R.1, T&R.3]
//  3. R: (χ) -----(Round3)--->(ẋ, ṫ)             [Check.2, T&R.1, T&R.2]
//  4. S: (ẋ,ṫ) ---(Round4)--->()                 [Check.3]
//
// -------------------------------------------------------------------------- //
// ROUNDS (OTe with fiat-shamir (*)):
//
//  0. Setup R & S: (...)---(κ × BaseOT)--->(...) [BaseOT]
//  1. R: (x)-------(Round1)--->(u,v_x,ẋ,ṫ)       [Ext.1, Ext.2, Ext.3, Check.1*, Check.2, T&R.1, T&R.2]
//  2. S: (u,ẋ,ṫ)---(Round2)--->(v_0,v_1)         [Ext.1, Ext.2, Ext.4, Check.1*, T&R.1, T&R.3, Check.3]
package softspoken

import "github.com/copperexchange/knox-primitives/pkg/core/curves"

const (
	// ------------------------ CONFIGURABLE PARAMETERS --------------------- //
	// Kappa (κ) is the computational security parameter in bits. Set |q| = κ
	// for a curve of prime order q. It is the size of the BaseOT seed batches
	// (used as PRG seeds) as well as the number of output elements per batch.
	Kappa = 256

	// lOTe is the ratio between scalars generated by the OTextension and the number
	// of BaseOT seed batches. Set to 1 for ForcedReuse (required for DKLS23).
	// All OTe/COTe inputs and outputs grow linearly with lOTe.
	lOTe = 1

	// Sigma (σ) is the statistical security parameter. Eta%σ=0.
	// Sigma is the numbet of bits to consume/discard in the consistency check.
	Sigma = 128

	// OTeWidth (ω) is the number of scalars processed per bit/"slot" of the OT
	// extension. For each choice bit in OTeInputChoices the sender provides,
	// `OTeWidth` scalars (in COTe), and both the sender and receiver obtain
	// `OTeWidth` scalars (in OTe and COTe).
	OTeWidth = 2

	// ---------------------- NON-CONFIGURABLE PARAMETERS ------------------- //
	// Zeta (ξ) is the batch size in bits used in the COTe protocol. For DKLS23,
	// ξ = l_OTe (κ + 2s), where s is their statistical security parameter. For
	// convenience, we set s = σ.
	Zeta = lOTe * (Kappa + 2*Sigma)

	// ZetaPrime (ξ') is the bit-length of pseudorandom seed expansions.
	ZetaPrime = Zeta + Sigma

	// number of blocks of size Sigma in the output batch.
	M = Zeta / Sigma

	// Equivalents in Bytes.
	KappaBytes     = Kappa >> 3     // KappaBytes (κ) is the computational security parameter in bytes
	ZetaBytes      = Zeta >> 3      // ZetaBytes (ξ) is the batch size in bytes.
	SigmaBytes     = Sigma >> 3     // SigmaBytes (σ) is the statistical security parameter in bytes
	ZetaPrimeBytes = ZetaPrime >> 3 // ZetaPrimeBytes (ξ') is the extended batch size in bytes.
	MBytes         = M >> 3         // M Bytes is the number of blocks in the consistency check in bytes
)

type (
	// --------------------------- (Random) OTe ----------------------------- //
	// OTeInputChoices (x_i) ∈ [ξ]bits are the choice bits for the OTe.
	OTeInputChoices = [ZetaBytes]byte

	// OTeSenderOutput (v_0, v_1) ∈ [2][ξ][ω][κ]bits is the output of the sender in
	// the OTe protocol ("InputOpt1" & "InputOpt2" in the diagram above).
	OTeSenderOutput = [2][Zeta][OTeWidth][KappaBytes]byte

	// OTeReceiverOutput (v_x) ∈ [ξ][ω][κ]bits is the output of the receiver in the
	// OTe protocol ("DeltaOpt" in the diagram above).
	OTeReceiverOutput = [Zeta][OTeWidth][KappaBytes]byte

	// ------------------------- (Correlated) COTe -------------------------- //
	// COTeInputOpt (α) ∈ [ξ][ω]curve.Scalar is the input of the sender in the COTe protocol (InputOpt).
	COTeInputOpt = [Zeta][OTeWidth]curves.Scalar

	// DerandomizeMask (τ) ∈ [ξ][ω]curve.Scalar is the correlation mask.
	DerandomizeMask [Zeta][OTeWidth]curves.Scalar

	// COTeSenderOutput (z_A) ∈ [ξ][ω]curve.Scalar is the output of the sender in
	// the COTe protocol, ("Correlation" in the diagram above).
	COTeSenderOutput = [Zeta][OTeWidth]curves.Scalar

	// COTeReceiverOutput (z_B) ∈ [ξ][ω]curve.Scalar is the output of the receiver in the COTe protocol (DeltaOpt).
	COTeReceiverOutput = [Zeta][OTeWidth]curves.Scalar

	// ---------------------------- EXTENSION ------------------------------- //
	// ExpansionMask (u^i) ∈ [κ][ξ']bits is the expanded and masked PRG outputs.
	ExpansionMask [Kappa][ZetaPrimeBytes]byte

	// ExtPackedChoices (x_i) ∈ [ξ']bits are the choice bits for the OTe filled with σ random values.
	ExtPackedChoices [ZetaPrimeBytes]byte

	// ExtOptions (t^i_0, t^i_1) ∈ [2][κ][ξ']bits are expansions of BaseOT results using a PRG.
	ExtOptions [2][Kappa][ZetaPrimeBytes]byte

	// ExtDeltaOpt (t^i_{Δ_i}) ∈ [κ][ξ']bits are the extended (via a PRG) baseOT deltaOpts.
	ExtDeltaOpt [Kappa][ZetaPrimeBytes]byte

	// ExtCorrelations (q_i) ∈ [κ][ξ']bits are the extended correlations, q^i = Δ_i • x + t^i.
	ExtCorrelations = [Kappa][ZetaPrimeBytes]byte

	// ------------------------ CONSISTENCY CHECK --------------------------- //
	// Challenge (χ_i) ∈ [M]×[σ]bits is the random challenge for the consistency check.
	Challenge [M][SigmaBytes]byte

	// ChallengeResponse (ẋ, ṫ) is the consistency check from the receiver,
	// to be verified by the Sender.
	ChallengeResponse struct {
		x_val [SigmaBytes]byte        // ẋ ∈ [σ]
		t_val [Kappa][SigmaBytes]byte // ṫ ∈ [κ][σ]bits
	}
)
