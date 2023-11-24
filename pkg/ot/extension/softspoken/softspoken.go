/*
Package softspoken implements of maliciously secure 1-out-of-2 Correlated Oblivious Transfer extension (COTe) protocol.

We follow the designs from:
- [SoftSpokenOT](https://eprint.iacr.org/2022/192) for the OT extension
- [MR19](https://eprint.iacr.org/2019/706) for the Derandomization ("Correlated")
We use the notation from ROT^{κ,l} from [KOS15](https://eprint.iacr.org/2015/546)
for the protocol description (Figure 10). We apply the "Fiat-Shamir" heuristic,
substituting the coin tossing required for the consistency check with the
hash of the public transcript (using an (*) to denote the changes). We also
apply the "Forced Reuse" technique from [DKLs23](https://eprint.iacr.org/2023/765)
fixing one single batch of input choice bits (LOTe=1) and reusing that batch
for all of the input batches.

// ============================= FUNCTIONALITIES ============================ //
OBLIVIOUS TRANSFER (OT)
At high level, a 1-out-of-2 OT (e.g., VSOT steps 1-9) realises this functionality:
┌------┐                      ┌------------------┐               ┌--------┐
|      |                      |                  |               |        |
|      |--> (Opt_0, Opt_1) -->|      1|2  OT     | <--(Choice)<--|        |
|Sender|                      |                  |               |Receiver|
|      |                      └------------------┘               |        |
|      |                               └-------> (DeltaOpt) -->  |        |
└------┘                                                         └--------┘
s.t. DeltaOpt = Opt_{Choice} = Opt_0 • (1-Choice) + Opt_1 • Choice

RANDOMISED OBLIVIOUS TRANSFER (ROT)
Instead, a Randomised OT (e.g. VSOT steps 1-7) randomly picks the Sender's input Options:
┌------┐                      ┌------------------┐               ┌--------┐
|      |                      |                  |               |        |
|      |                      |      1|2 ROT     | <--(Choice)<--|        |
|Sender|                      |                  |               |Receiver|
|      |                      └------------------┘               |        |
|      | <----- (Opt_0, Opt_1) <--------┴-------> (DeltaOpt) --> |        |
└------┘                                                         └--------┘
s.t. DeltaOpt = Opt_{Choice} = Opt_0 • (1-Choice) + Opt_1 • Choice

CORRELATED OBLIVIOUS TRANSFER (COT)
In contrast, a single "Correlated" OT (e.g., SoftspokenOT) realises the following functionality:
┌------┐                      ┌------------------┐               ┌--------┐
|      |                      |                  |               |        |
|      |----> (InputOpt) ---->|      1|2  COT    | <--(Choice)<--|        |
|Sender|                      |                  |               |Receiver|
|      |                      └------------------┘               |        |
|      | <----- (Correlation) <--------┴-------> (DeltaOpt) ---> |        |
└------┘                                                         └--------┘
s.t. Correlation = Choice • InputOpt - DeltaOpt

The Options, DeltaOpt and Correlation are elements of a group (e.g. Z_2,
Z_{2^N}, F_q, elliptic curve points), whereas Choice is always a bit.
OT EXTENSION (OTe, COTe)
An "Extension" (both for OT and COT with Options of length κ) makes use of a
PRG to expand each Base OT with κ-bit messages into η-bit message OTs.
*/
package softspoken

import (
	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
)

const (
	Kappa = base.ComputationalSecurity // κ, the computational security parameter in bits.
	Sigma = Kappa                      // σ, the statistical security parameter (Eta%σ=0), bits to consume/discard in the consistency check. σ = κ for Fiat-Shamir.
	Xi    = (Kappa + 2*Sigma)          // ξ, the COTe batch size. ξ = LOTe (κ + 2s) for DKLs23.

	// SET DYNAMICALLY TO ALLOW VARIABLE-SIZE INPUTS
	// - LOTe is the number of ξ×κ-bit OTe batches. For "Forced Reuse" (as in DKLS23), it is instead the number of reuses of the output OTe batch.
	// - eta (η = LOTe*ξ) is the OTe batch size without the statistical redundancy.
	// - etaPrime (η' = η + σ) is the full OT expansion size (including the statistical redundancy).
	// - M (= η/σ) is the number of σ-bit consistency check challenges.
	// - Omega (ω), the number of scalars correlated in COTe per slot of the OT extension. ω = 2 for DKLs23.

	// BYTES
	KappaBytes = Kappa >> 3 // κ, the computational security parameter in bytes.
	XiBytes    = Xi >> 3    // ξ, the batch size in bytes.
	SigmaBytes = Sigma >> 3 // σ, the statistical security parameter in bytes.
)

type (
	/*.---------------------------- (Random) OTe ----------------------------.*/

	OTeInputChoices = [][XiBytes]byte        // x_i ∈ [LOTe][ξ]bits, the OTe input choice bits.
	OTeMessage      = [][Xi][KappaBytes]byte // ∈ [LOTe][ξ][κ]bits, type for the OTe messages {v_0, v_1, v_x}.

	/*------------------------ (Correlated OTe) COTe ------------------------.*/

	COTeMessage = [][Xi][]curves.Scalar // [L][ξ][ω]curve.Scalar, type of COTe inputs, masks and outputs: {α, τ, z_A, z_B}

	/*.----------------------------- EXTENSION ------------------------------.*/

	ExtMessage       [Kappa][]byte // ∈ [κ][η']bits, type for the OT expansions, ∈ [κ][η']bits after the consistency check.
	ExtPackedChoices []byte        // x_i ∈ [η']bits, the OTe choice bits + σ random values.

	/*.------------------------- CONSISTENCY CHECK --------------------------.*/

	Challenge  [][SigmaBytes]byte // χ_i ∈ [M=η/σ]×[σ]bits is the random challenge for the consistency check.
	Witness    [][SigmaBytes]byte // r ∈ [κ][σ]bits is the witness for the Fiat-Shamir transform.
	Commitment [][SigmaBytes]byte // c ∈ [κ*σ]bits is the witness commitment for the Fiat-Shamir transform.

	// ChallengeResponse (ẋ, ṫ) is the OTe consistency check from the receiver, to be verified by the Sender.
	ChallengeResponse struct {
		x_val [SigmaBytes]byte        // ẋ ∈ [σ]
		t_val [Kappa][SigmaBytes]byte // ṫ ∈ [κ][σ]bits
	}
)
