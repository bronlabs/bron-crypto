/*
Package softspoken implements of maliciously secure 1-out-of-2 Correlated Oblivious Transfer extension (COTe) protocol.

We follow the designs from:
- [SoftSpokenOT](https://eprint.iacr.org/2022/192) for the OT extension
- [MR19](https://eprint.iacr.org/2019/706) for the Derandomization ("Correlated")
We use the notation from ROT^{κ,l} from [KOS15](https://eprint.iacr.org/2015/546)
for the protocol description (Figure 10). We apply the "Fiat-Shamir" heuristic,
substituting the coin tossing required for the consistency check with the
hash of the public transcript (using an (*) to denote the changes). We also
apply the "Forced Reuse" technique from [DKLs24](https://eprint.iacr.org/2023/765)
fixing one single batch of input choice bits (LOTe=1) and reusing that batch
for all of the input batches.

// ============================= FUNCTIONALITIES ============================ //
OBLIVIOUS TRANSFER (OT)
At high level, a 1-out-of-2 OT (e.g., VSOT steps 1-9) realises this functionality:
┌------┐                      ┌------------------┐               ┌--------┐
|      |                      |                  |               |        |
|      |----> (v_0, v_1) ---> |      1|2  OT     | <-----(x)<----|        |
|Sender|                      |                  |               |Receiver|
|      |                      └------------------┘               |        |
|      |                               └---------> (v_x) ----->  |        |
└------┘                                                         └--------┘
s.t. v_x = v_0 • (1-x) + v_1 • x

RANDOMISED OBLIVIOUS TRANSFER (ROT)
Instead, a Randomised OT randomly picks the Sender's input Options:
┌------┐                      ┌------------------┐               ┌--------┐
|      |                      |                  |               |        |
|      |                      |      1|2 ROT     | <----(x)<-----|        |
|Sender|                      |                  |               |Receiver|
|      |                      └------------------┘               |        |
|      | <----- (v_0, v_1) <------------┴----------> (v_x) ----> |        |
└------┘                                                         └--------┘
s.t. DeltaOpt = Opt_{Choice} = Opt_0 • (1-Choice) + Opt_1 • Choice

CORRELATED OBLIVIOUS TRANSFER (COT)
In contrast, a "Correlated" OT realises the following functionality:
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
	Sigma = base.ComputationalSecurity // σ, the statistical security parameter (Eta%σ=0). σ = κ for Fiat-Shamir.

	// Xi = (2*Kappa + 2*Sigma) // ξ, the number o*f OTe batches. ξ = (κ + 2s) for DKLs24.

	// SET DYNAMICALLY TO ALLOW VARIABLE-SIZE INPUTS
	// - κ is the bit-length of each OTe/COTe element (s.t. each κ-bit OTe element maps to one scalar in COTe).
	// - LOTe is the number of OTe/COTe elements per OTe/COTe message. LOTe * κ corresponds to the bit-length of each OTe message.
	// - ξ, the number of the OTe/COTe messages per OTe/COTe batch. ξ = (κ + 2s) for DKLs24.
	// - eta (η = LOTe*ξ) is the total number of μ-bit OTe elements without the statistical redundancy.
	// - etaPrime (η' = η + σ) is the full OT expansion size (including the statistical redundancy).
	// - M (= η/σ) is the number of σ-bit consistency check challenges.

	// BYTES
	KappaBytes = Kappa >> 3 // κ, the computational security parameter in bytes.
	SigmaBytes = Sigma >> 3 // σ, the statistical security parameter in bytes.
)

type (
	/*.---------------------------- (Random) OTe ----------------------------.*/
	OTeMessage      = []byte       // [LOTe*κ]bits, individual OTe message made of LOTe elements of μ bits.
	OTeMessageBatch = []OTeMessage // [ξ][LOTe*κ]bits, the OTe batch of ξ messages of size LOTe*μ bits {v_0, v_1, v_x}.
	OTeChoices      = []byte       // [ξ]bits, the OTe input choice bits {x}.

	/*------------------------ (Correlated OTe) COTe ------------------------.*/

	COTeMessage      = []curves.Scalar // [LOTe]curve.Scalar, COTe inputs & masks & outputs: {α, τ, z_A, z_B}
	COTeMessageBatch = []COTeMessage   // [ξ][LOTe]curve.Scalar, type of COTe inputs, masks and outputs: {α, τ, z_A, z_B}

	/*.----------------------------- EXTENSION ------------------------------.*/

	ExtMessageBatch  = [Kappa][]byte // ∈ [κ][ξ*LOTe]bits, type for the OT expansions, ∈ [κ][η']bits after the consistency check.
	ExtPackedChoices = []byte        // x_i ∈ [ξ+σ]bits, the OTe choice bits + σ random values.

	/*.------------------------- CONSISTENCY CHECK --------------------------.*/

	Challenge  = [][SigmaBytes]byte // χ_i ∈ [M=η/σ][σ]bits is the random challenge for the consistency check.
	Witness    = [][SigmaBytes]byte // r ∈ [κ][σ]bits is the witness for the Fiat-Shamir transform.
	Commitment = [][SigmaBytes]byte // c ∈ [κ*σ]bits is the witness commitment for the Fiat-Shamir transform.

	// ChallengeResponse (ẋ, ṫ) is the OTe consistency check from the receiver, to be verified by the Sender.
	ChallengeResponse struct {
		X_val [SigmaBytes]byte        // ẋ ∈ [σ]
		T_val [Kappa][SigmaBytes]byte // ṫ ∈ [κ][σ]bits
	}
)
