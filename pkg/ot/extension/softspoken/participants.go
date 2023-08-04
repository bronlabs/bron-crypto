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
fixing one single batch of input choice bits (l_OTe=1) and reusing that batch
for all of the input batches.
*/
package softspoken

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/ot/base/vsot"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/merlin"
)

const (
	// ------------------------ CONFIGURABLE PARAMETERS --------------------- //
	// Kappa (κ) is the computational security parameter in bits. Set |q| = κ
	// for a curve of prime order q. It is the size of the BaseOT seed batches
	// (used as PRG seeds) as well as the number of output elements per batch.
	Kappa = 256

	// Sigma (σ) is the statistical security parameter. Eta%σ=0.
	// Sigma is the numbet of bits to consume/discard in the consistency check.
	Sigma = 256

	// ROTeWidth (ω) is the number of scalars processed per bit/"slot" of the OT
	// extension. For each choice bit in OTeInputChoices the sender provides,
	// `ROTeWidth` scalars (in COTe), and both the sender and receiver obtain
	// `ROTeWidth` scalars (in OTe and COTe).
	ROTeWidth = 2

	// ---------------------- NON-CONFIGURABLE PARAMETERS ------------------- //
	// Xi (ξ) is the batch size in bits used in the COTe protocol. For DKLS23,
	// ξ = l_OTe (κ + 2s), where s is their statistical security parameter. For
	// convenience, we set s = σ
	Xi = (Kappa + 2*Sigma)

	// N is the number of options in the OT, N = 2 for 1-out-of-2-OT.
	N = 2

	// SET DYNAMICALY TO ALLOW VARIABLE-SIZE INPUTS
	// L is the number of ξ×ω×κ-bit batches after in the expansion. For "Forced Reuse"
	// (as in DKLS23), it is instead the number of reuses of the output OTe batch.
	// L = ...

	// eta (η) is the OT expansion size without the statistical redundancy.
	// Eta = L*ξ

	// etaPrime (η') is the full OT expansion size. EtaPrime = L*ξ + σ
	// EtaPrime = Eta + σ

	// M is the number of consistency check challenges. M = η/σ
	// M = eta/Sigma

	// BYTES
	KappaBytes = Kappa >> 3 // KappaBytes (κ) is the computational security parameter in bytes
	XiBytes    = Xi >> 3    // XiBytes (ξ) is the batch size in bytes.
	SigmaBytes = Sigma >> 3 // SigmaBytes (σ) is the statistical security parameter in bytes
)

type (
	// --------------------------- (Random) OTe ----------------------------- //

	// OTeInputChoices (x_i) ∈ [L][ξ]bits are the input choice bits for the OTe
	// ("Choice" in the diagram above)
	OTeInputChoices = [][XiBytes]byte

	// OTeSenderOutput (v_0, v_1) ∈ [N][L][ξ][ω][κ]bits is the output of the sender
	// in the OTe protocol ("InputOpt1" & "InputOpt2" in the diagram above)
	OTeSenderOutput = [N][][Xi][ROTeWidth][KappaBytes]byte

	// OTeReceiverOutput (v_x) ∈ [L][ξ][ω][κ]bits is the output of the receiver in the
	// OTe protocol ("DeltaOpt" in the diagram above)
	OTeReceiverOutput = [][Xi][ROTeWidth][KappaBytes]byte

	// ----------------------- (Correlated OTe) COTe ------------------------ //

	// COTeInputOpt (α) ∈ [L'][ξ][ω]curve.Scalar is the sender input to COTe
	// protocol ("InputOpt" in the diagram above)
	COTeInputOpt = [][Xi][ROTeWidth]curves.Scalar

	// DerandomizeMask (τ) ∈ [L'][ξ][ω]curve.Scalar is the correlation mask
	DerandomizeMask [][Xi][ROTeWidth]curves.Scalar

	// COTeSenderOutput (z_A) ∈ [L'][ξ][ω]curve.Scalar is the output of the sender
	// in the COTe protocol, ("Correlation" in the diagram above)
	COTeSenderOutput = [][Xi][ROTeWidth]curves.Scalar

	// COTeReceiverOutput (z_B) ∈ [L'][ξ][ω]curve.Scalar is the receiver output
	// in the COTe protocol ("DeltaOpt" in the diagram above)
	COTeReceiverOutput = [][Xi][ROTeWidth]curves.Scalar

	// ---------------------------- EXTENSION ------------------------------- //

	// ExpansionMask (u^i) ∈ [κ][η']bits is the expanded and masked PRG outputs
	ExpansionMask [Kappa][]byte

	// ExtPackedChoices (x_i) ∈ [η']bits are the choice bits for the OTe filled with σ random values.
	ExtPackedChoices []byte

	// ExtOptions (t^i_0, t^i_1) ∈ [2][κ][η']bits are expansions of BaseOT results using a PRG.
	ExtOptions [N][Kappa][]byte

	// ExtDeltaOpt (t^i_{Δ_i}) ∈ [κ][η']bits are the extended (via a PRG) baseOT deltaOpts.
	ExtDeltaOpt [Kappa][]byte

	// ExtCorrelations (q_i) ∈ [κ][η']bits are the extended correlations, q^i = Δ_i • x + t^i
	ExtCorrelations [Kappa][]byte

	// ------------------------ CONSISTENCY CHECK --------------------------- //
	// Challenge (χ_i) ∈ [M=η/σ]×[σ]bits is the random challenge for the consistency check.
	Challenge [][SigmaBytes]byte

	// ChallengeResponse (ẋ, ṫ) is the consistency check from the receiver,
	// to be verified by the Sender.
	ChallengeResponse struct {
		x_val [SigmaBytes]byte        // ẋ ∈ [σ]
		t_val [Kappa][SigmaBytes]byte // ṫ ∈ [κ][σ]bits
	}
)

type Receiver struct {
	// baseOtSeeds (k^i_0, k^i_1) ∈ [κ][2][κ]bits are the options used while
	//  of playing the sender in a base OT protocol. They act as seeds to COTe.
	baseOtSeeds *vsot.SenderOutput

	// extPackedChoices (x_i ∈ [η']bits) are the extended packed choices of the receiver.
	extPackedChoices ExtPackedChoices

	// sid is the unique identifier of the current session (sid in DKLs19)
	sid []byte

	// transcript is the transcript containing the protocol's publicly exchanged messages.
	transcript transcripts.Transcript

	// curve is the elliptic curve used in the protocol.
	curve *curves.Curve

	// useForcedReuse is a flag that indicates whether the protocol should use forced reuse.
	useForcedReuse bool
}

type Sender struct {
	// baseOtSeeds (Δ_i ∈ [κ]bits, k^i_{Δ_i} ∈ [κ][κ]bits) are the results
	// of playing the receiver in a base OT protocol. They act as seeds of COTe.
	baseOtSeeds *vsot.ReceiverOutput

	// sid is the unique identifier of the current session (sid in DKLs19)
	sid []byte

	// transcript is the transcript containing the protocol's publicly exchanged messages.
	transcript transcripts.Transcript

	// curve is the elliptic curve used in the protocol.
	curve *curves.Curve

	// useForcedReuse is a flag that indicates whether the protocol should use forced reuse.
	useForcedReuse bool
}

// NewCOtReceiver creates a `Receiver` instance for the SoftSpokenOT protocol.
// The `baseOtResults` are the results of playing the sender role in κ baseOTs.
func NewCOtReceiver(
	baseOtResults *vsot.SenderOutput,
	uniqueSessionId []byte,
	transcript transcripts.Transcript,
	curve *curves.Curve,
	useForcedReuse bool,
) (*Receiver, error) {
	if transcript == nil {
		transcript = merlin.NewTranscript("KNOX_PRIMITIVES_SOFTSPOKEN_COTe")
	}
	transcript.AppendMessage([]byte("session_id"), uniqueSessionId)
	return &Receiver{
		baseOtSeeds:    baseOtResults,
		sid:            uniqueSessionId,
		transcript:     transcript,
		curve:          curve,
		useForcedReuse: useForcedReuse,
	}, nil
}

// NewCOtSender creates a `Sender` instance for the SoftSpokenOT protocol.
// The `baseOtResults` are the results of playing the receiver role in κ baseOTs.
func NewCOtSender(
	baseOtResults *vsot.ReceiverOutput,
	uniqueSessionId []byte,
	transcript transcripts.Transcript,
	curve *curves.Curve,
	useForcedReuse bool,
) (*Sender, error) {
	if transcript == nil {
		transcript = merlin.NewTranscript("KNOX_PRIMITIVES_SOFTSPOKEN_COTe")
	}
	transcript.AppendMessage([]byte("session_id"), uniqueSessionId)
	return &Sender{
		baseOtSeeds:    baseOtResults,
		sid:            uniqueSessionId,
		transcript:     transcript,
		curve:          curve,
		useForcedReuse: useForcedReuse,
	}, nil
}
