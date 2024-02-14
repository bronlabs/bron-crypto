/*
Package softspoken implements a maliciously secure 1-out-of-2 Oblivious Transfer extension (OTe) protocol.

We follow the designs from:
- [SoftSpokenOT](https://eprint.iacr.org/2022/192) for the OT extension
- [MR19](https://eprint.iacr.org/2019/706) for the Derandomization ("Correlated")
We use the notation from ROT^{κ,l} from [KOS15](https://eprint.iacr.org/2015/546)
for the protocol description (Figure 10). We apply the "Fiat-Shamir" heuristic,
substituting the coin tossing required for the consistency check with the
hash of the public transcript.

OT EXTENSION (OTe, COTe)
An "Extension" (both for OT and COT with Options of length κ) makes use of a
PRG to expand each Base OT with κ-bit messages into η-bit message OTs.
*/
package softspoken

import (
	"github.com/copperexchange/krypton-primitives/pkg/ot"
)

const (
	Kappa      = ot.Kappa      // κ, the computational security parameter in bits.
	Sigma      = ot.Kappa      // σ, the statistical security parameter (Eta%σ=0). σ = κ for Fiat-Shamir.
	KappaBytes = ot.KappaBytes // κ, the computational security parameter in bytes.
	SigmaBytes = ot.KappaBytes // σ, the statistical security parameter in bytes.

	// SET DYNAMICALLY TO ALLOW VARIABLE-SIZE INPUTS
	// - L is the number of OT elements per OT message.
	// - Xi (ξ), the number of the OTe/COTe messages per OTe/COTe batch. ξ=(κ+2s) for DKLs24.
	// - eta (η=L*ξ) is the total number of κ-bit OT elements after expansion, minus the statistical redundancy.
	// - etaPrime (η'=η+σ) is the full OT expansion size (including the statistical redundancy).
	// - M (= η/σ) is the number of σ-bit consistency check challenges.
)

type (
	/*.----------------------------- EXTENSION ------------------------------.*/

	ExtMessageBatch  = [Kappa][]byte // ∈ [κ][ξ*L]bits, type for the OT expansions, ∈ [κ][η']bits after the consistency check.
	ExtPackedChoices = ot.ChoiceBits // x_i ∈ [ξ+σ]bits, the OTe choice bits + σ random values.

	/*.------------------------- CONSISTENCY CHECK --------------------------.*/

	Challenge  = [][SigmaBytes]byte // χ_i ∈ [M=η/σ][σ]bits is the random challenge for the consistency check.
	Witness    = [][SigmaBytes]byte // r ∈ [κ][σ]bits is the witness for the Fiat-Shamir transform.
	Commitment = [][SigmaBytes]byte // c ∈ [κ][σ]bits is the witness commitment for the Fiat-Shamir transform.

	// ChallengeResponse (ẋ, ṫ) is the OTe consistency check from the receiver, to be verified by the Sender.
	ChallengeResponse struct {
		X_val [SigmaBytes]byte        // ẋ ∈ [σ]bits
		T_val [Kappa][SigmaBytes]byte // ṫ ∈ [κ][σ]bits
	}
)
