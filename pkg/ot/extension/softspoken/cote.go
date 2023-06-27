package softspoken

import (
	"crypto/rand"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/ot/base/simplest"
	"golang.org/x/crypto/sha3"
)

// TODO: Map to curve elements (see how KOS15 does it)
// TODO: Choose values for the parameters (Kappa, s)
// TODO: Binary field addition for consistency check
// TODO: refactor to use hash module
//      -> Code hash function using AES primitives and use it for H
//TODO: refactor to have a secure rand module in core

const (
	// below are the "cryptographic parameters", including computational and statistical,
	// ------------------------ CONFIGURABLE PARAMETERS --------------------- //
	// Kappa is the computational security parameter.
	Kappa = 256

	// L is the batch size used in the cOT functionality.
	L = 256

	// s is the statistical security parameter. Must divide L (L%s=0) for SoftSpokenOT.
	s = 64

	// ---------------------- NON-CONFIGURABLE PARAMETERS ------------------- //
	// keyCount is the number of scalars to choose from in the BaseOT, as well as
	//  the number of shares _per_ choice of the cOT. Set to 2 for 1-out-of-2 OT
	//  and one share per party.
	keyCount = 2

	// length of pseudorandom seed expansion
	LPrime = L + s

	// number of blocks in the consistency check
	m = L / s

	// Equivalents in Bytes
	KappaBytes  = Kappa >> 3
	LBytes      = L >> 3
	sBytes      = s >> 3
	LPrimeBytes = LPrime >> 3
)

type Receiver struct {
	// baseOtSendOutputs () are the results of playing the sender role in a base
	//  OT protocol. They serve as inputs to the COTe protocol.
	baseOtSendOutputs *simplest.SenderOutput

	// OutputExtPackedChoices (x_i) are the choice bits from the base OTs.
	OutputExtPackedChoices [LPrimeBytes]byte

	// OutputWords (v_{{x_j},j}) are the results of hashing the expansion of the OTs.
	OutputWords [L][KappaBytes]byte

	curve           *curves.Curve
	uniqueSessionId [simplest.DigestSize]byte // store this between rounds
}

type Sender struct {
	// baseOtRecOutputs (Δ_i, k^i_{Δ_i}) are the results of playing the receiver
	//  role in a base OT protocol. They serve as inputs to the COTe protocol.
	baseOtRecOutputs *simplest.ReceiverOutput

	// extChosenWords (t^i_{Δ_i}) are the results of expanding the base OT results using a PRG .
	extChosenWords [Kappa][LPrimeBytes]byte

	// extCorrelations (q_i) are the extended correlations, such that:
	//    q_i = Δ_i • x + t_i
	extCorrelations [Kappa][LPrimeBytes]byte

	// OutputCorrelations (v_0_i, v_1_i) are the extended OT correlations after
	//  transposition and randomization
	OutputCorrelations [keyCount][L][KappaBytes]byte

	// OutputBasePackedChoices (Δ_i) are the choice bits from the base OTs.
	OutputBasePackedChoices *[]byte

	curve *curves.Curve
}

// NewCOtReceiver creates a `Receiver` instance for the SoftSpokenOT protocol.
// The `baseOtResults` are the results of playing the sender role in kappa baseOTs.
func NewCOtReceiver(baseOtResults *simplest.SenderOutput, curve *curves.Curve) *Receiver {
	return &Receiver{
		baseOtSendOutputs: baseOtResults,
		curve:             curve,
	}
}

// NewCOtSender creates a `Sender` instance for the SoftSpokenOT protocol.
// The `baseOtResults` are the results of playing the receiver role in kappa baseOTs.
func NewCOtSender(baseOtResults *simplest.ReceiverOutput, curve *curves.Curve) *Sender {
	return &Sender{
		baseOtRecOutputs:        baseOtResults,
		OutputBasePackedChoices: &baseOtResults.PackedRandomChoiceBits,
		curve:                   curve,
	}
}

// Round1Output contains the expanded and masked PRG outputs u_i
type Round1Output struct {
	U [Kappa][LPrimeBytes]byte
}

// Round1Extend uses the PRG to extend the basseOT results.
func (receiver *Receiver) Round1Extend(uniqueSessionId [simplest.DigestSize]byte, InputPackedChoices [LBytes]byte) (*Round1Output, error) {

	// Copy uniqueSessionId into receiver
	copy(receiver.uniqueSessionId[:], uniqueSessionId[:])

	// (E.1) Store the input choice vector and fill the rest with random values
	copy(receiver.OutputExtPackedChoices[:LBytes], InputPackedChoices[:])
	if _, err := rand.Read(receiver.OutputExtPackedChoices[LBytes:]); err != nil {
		return nil, errs.WrapFailed(err, "sampling random bits for extended choice vector")
	}

	// (E.2) Expand the baseOT results using them as seed to the PRG
	// expandedOtResults are the results of expanding the base OT results using a PRG.
	expandedOtResults := new([keyCount][Kappa][LPrimeBytes]byte)
	for i := 0; i < Kappa; i++ {
		for j := 0; j < keyCount; j++ {
			shake := sha3.NewCShake256(uniqueSessionId[:], []byte("Copper_Softspoken_COTe"))
			if _, err := shake.Write(receiver.baseOtSendOutputs.OneTimePadEncryptionKeys[i][j][:]); err != nil {
				return nil, errs.WrapFailed(err, "writing seed OT into shake in SoftSpoken COTe")
			}
			// This is the core pseudorandom expansion of the secret OT input seeds k_i^0 and k_i^1
			// use the uniqueSessionId as the "domain separator", and the _secret_ seed as the input
			if _, err := shake.Read(expandedOtResults[j][i][:]); err != nil {
				return nil, errs.WrapFailed(err, "reading from shake in SoftSpoken COTe")
			}
		}
	}

	// (E.3) Compute u_i and send it
	round1Output := &Round1Output{}
	for i := 0; i < Kappa; i++ {
		for j := 0; j < LPrimeBytes; j++ {
			round1Output.U[i][j] = expandedOtResults[0][i][j] ^ expandedOtResults[1][i][j] ^ receiver.OutputExtPackedChoices[j]
		}
	}

	// (T&R.1) Transpose t
	transposedOtResults := transposeBooleanMatrix(expandedOtResults[0])

	// (T&R.2) Hash the L first rows of t using the index as salt, get rid of the rest.
	for i := int(0); i < L; i++ {
		hash := sha3.New512()
		idx_bytes := intToByteArr(i)
		if _, err := hash.Write(idx_bytes[:]); err != nil {
			return nil, errs.WrapFailed(err, "writing index into Sha512 for SoftSpoken COTe")
		}
		if _, err := hash.Write(transposedOtResults[i][:]); err != nil {
			return nil, errs.WrapFailed(err, "writing transposed matrix into Sha512 for SoftSpoken COTe")
		}
		copy(receiver.OutputWords[i][:], hash.Sum(nil))
	}

	return round1Output, nil
}

// Round2Output contains the challenge chi_i and the derandomization values.
type Round2Output struct {
	Chi [m + 1][sBytes]byte
	D   [m + 1][keyCount]curves.Scalar
}

// Round2Extend uses the PRG to extend the basseOT results. It also sends a
// challenge to the receiver in order to check the consistency.
func (sender *Sender) Round2Extend(uniqueSessionId [simplest.DigestSize]byte, Round1Output *Round1Output) (*Round2Output, error) {

	// (E.2) Expand the baseOT results using them as seed to the PRG
	// receiver.expandedOtResults[0]
	for i := 0; i < Kappa; i++ {
		shake := sha3.NewCShake256(uniqueSessionId[:], []byte("Copper_Softspoken_COTe"))
		if _, err := shake.Write(sender.baseOtRecOutputs.OneTimePadDecryptionKey[i][:]); err != nil {
			return nil, errs.WrapFailed(err, "writing seed OT into shake in SoftSpoken COTe")
		}
		// This is the core pseudorandom expansion of the secret OT input seeds k_i^0 and k_i^1
		// use the uniqueSessionId as the "domain separator", and the _secret_ seed as the input
		if _, err := shake.Read(sender.extChosenWords[i][:]); err != nil {
			return nil, errs.WrapFailed(err, "reading from shake in COTe")
		}
	}

	// (E.4) Compute q_i
	for i := 0; i < Kappa; i++ {
		for j := 0; j < LPrimeBytes; j++ {
			sender.extCorrelations[i][j] = sender.baseOtRecOutputs.PackedRandomChoiceBits[i]&Round1Output.U[i][j] ^ sender.extChosenWords[i][j]
		}
	}

	// (C.1) Sample and send chi_i as challenge to check consistency
	round2Output := &Round2Output{}
	for i := 0; i < m+1; i++ {
		if _, err := rand.Read(round2Output.Chi[i][:]); err != nil {
			return nil, errs.WrapFailed(err, "sampling random bits for challenge chi")
		}
	}

	// (T&R.1) Transpose
	transposedExtCorrelations := transposeBooleanMatrix(sender.extCorrelations)

	// (T&R.3) Hash the rows of q with/without Δ
	maskedTransposedExtCorrelations := new([LPrimeBytes]byte)
	for j := int(0); j < L; j++ {
		hash := sha3.New512()
		idx_bytes := intToByteArr(j)
		if _, err := hash.Write(idx_bytes[:]); err != nil {
			return nil, errs.WrapFailed(err, "writing index into Sha512 for SoftSpoken COTe")
		}
		// v_0_j = H (j || q_j)
		if _, err := hash.Write(transposedExtCorrelations[j][:]); err != nil {
			return nil, errs.WrapFailed(err, "writing transposed q_j into Sha512 for SoftSpoken COTe")
		}
		// v_1_j = H (j || q_j + Δ)
		copy(sender.OutputCorrelations[0][j][:], hash.Sum(nil))
		for i := int(0); i < Kappa; i++ {
			maskedTransposedExtCorrelations[i] = transposedExtCorrelations[j][i] ^ sender.baseOtRecOutputs.PackedRandomChoiceBits[i]
		}
		if _, err := hash.Write(maskedTransposedExtCorrelations[:]); err != nil {
			return nil, errs.WrapFailed(err, "writing transposed q_j + Delta into Sha512 for SoftSpoken COTe")
		}
		copy(sender.OutputCorrelations[1][j][:], hash.Sum(nil))
	}

	// (Derandom.2) Add values to output and send derandomization values.

	return round2Output, nil
}

// Round2Output this is Alice's response to Bob in COTe
type Round3Output struct {
	x_check [sBytes]byte
	t_check [Kappa][sBytes]byte
}

// Round3ProveConsistency answers to the challenge of S.
func (receiver *Receiver) Round3ProveConsistency(uniqueSessionId [simplest.DigestSize]byte, Round2Output *Round2Output) (*Round3Output, error) {
	// (C.2) Compute the challenge response x, t^i \forall i \in [kappa]
	round3Output := &Round3Output{}
	for i := 0; i < LBytes; i = i + sBytes {
		round3Output.x_check[i] = receiver.OutputExtPackedChoices[i : i+sBytes]
	}

	// (Derandom.2) Compute the derandomization and output result.

	return nil, nil
}

// Round4CheckConsistency checks the consistency using the challenge response.
func (sender *Sender) Round4CheckConsistency(uniqueSessionId [simplest.DigestSize]byte) error {
	// (C.3) Check the consistency of the challenge response computing q^i

	//  and checking q^i = t^i + \Delta_i • x \forall i \in [kappa]. If not, abort.

	return nil
}
