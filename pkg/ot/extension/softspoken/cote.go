package softspoken

import (
	"crypto/rand"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/ot/base/simplest"
	"golang.org/x/crypto/sha3"
)

// TODO: Binary field addition/multiplication outside of the curve (faster) for consistency.
// TODO: refactor to use hash module
//      -> Code hash function using AES primitives and use it for H
//TODO: refactor to have a secure rand module in core

const (
	// below are the "cryptographic parameters", including computational and statistical,
	// ------------------------ CONFIGURABLE PARAMETERS --------------------- //
	// Kappa (κ) is the computational security parameter (λ in SoftSpokenOT)
	Kappa = 256

	// L is the batch size used in the cOT functionality.
	L = 256

	// s is the statistical security parameter. Must divide L (L%s=0) for SoftSpokenOT.
	//  We set it to kappa in order to perform the validation directly in the curve.
	s = 256

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
	// baseOtSendOutputs () are the results of playing the sender role in a base
	//  OT protocol. They serve as inputs to the COTe protocol.
	baseOtSendOutputs *simplest.SenderOutput

	// ExpOTeResults (t^i) are the results of expanding the base OT results using a PRG.
	ExpOTeResults [KeyCount][Kappa][LPrimeBytes]byte

	// OutExtPackChoices (x_i) are the choice bits from the base OTs.
	OutExtPackChoices [LPrimeBytes]byte

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

	// extCorrelations (q_i)∈ [κ][L']bits are the extended correlations, such that:
	//    q_i = Δ_i • x + t_i
	extCorrelations [Kappa][LPrimeBytes]byte

	// OutputCorrelations (v_0_i, v_1_i) are the extended OT correlations after
	//  transposition and randomization
	OutputCorrelations [KeyCount][L][KappaBytes]byte

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
	copy(receiver.OutExtPackChoices[:LBytes], InputPackedChoices[:])
	if _, err := rand.Read(receiver.OutExtPackChoices[LBytes:]); err != nil {
		return nil, errs.WrapFailed(err, "sampling random bits for extended choice vector")
	}

	// (E.2) Expand the baseOT results using them as seed to the PRG
	// expandedOtResults are the results of expanding the base OT results using a PRG.
	for i := 0; i < Kappa; i++ {
		for j := 0; j < KeyCount; j++ {
			shake := sha3.NewCShake256(uniqueSessionId[:], []byte("Copper_Softspoken_COTe"))
			if _, err := shake.Write(receiver.baseOtSendOutputs.OneTimePadEncryptionKeys[i][j][:]); err != nil {
				return nil, errs.WrapFailed(err, "writing seed OT into shake in SoftSpoken COTe")
			}
			// This is the core pseudorandom expansion of the secret OT input seeds k_i^0 and k_i^1
			// use the uniqueSessionId as the "domain separator", and the _secret_ seed as the input
			if _, err := shake.Read(receiver.ExpOTeResults[j][i][:]); err != nil {
				return nil, errs.WrapFailed(err, "reading from shake in SoftSpoken COTe")
			}
		}
	}

	// (E.3) Compute u_i and send it
	round1Output := &Round1Output{}
	for i := 0; i < Kappa; i++ {
		for j := 0; j < LPrimeBytes; j++ {
			round1Output.U[i][j] = receiver.ExpOTeResults[0][i][j] ^ receiver.ExpOTeResults[1][i][j] ^ receiver.OutExtPackChoices[j]
		}
	}

	// (T&R.1) Transpose t
	transposedOtResults := transposeBooleanMatrix(receiver.ExpOTeResults[0])

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

// Round2Output contains the challenge chi_i.
type Round2Output struct {
	Chi [m + 1][sBytes]byte
}

// Round2Extend uses the PRG to extend the basseOT results. It also sends a
// challenge to the receiver in order to check the consistency.
func (sender *Sender) Round2Extend(uniqueSessionId [simplest.DigestSize]byte, Round1Output *Round1Output) (*Round2Output, error) {

	// (E.2) Expand the baseOT results using them as seed to the PRG
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
		hash := sha3.New256()
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
	return round2Output, nil
}

// Round2Output this is Alice's response to Bob in COTe
type Round3Output struct {
	x_check curves.Scalar        // plain x in the protocol
	t_check [Kappa]curves.Scalar // plain t^i in the protocol
}

// Round3ProveConsistency answers to the challenge of S.
func (receiver *Receiver) Round3ProveConsistency(round2Output *Round2Output) (*Round3Output, error) {
	var err error

	// (C.2) Compute the challenge response x, t^i \forall i \in [kappa]
	round3Output := &Round3Output{}
	// 		x = x^hat_{m+1} ...
	round3Output.x_check, err = receiver.curve.Scalar.SetBytes(receiver.OutExtPackChoices[LBytes : LBytes+sBytes])
	if err != nil {
		return nil, errs.WrapFailed(err, "Last OutExtPackChoices scalar from bytes for SoftSpoken COTe check")
	}
	// 		                ... + Σ{j=0}^{m-1} \chi_j • x_hat_j
	for j := 0; j < m; j++ {
		x_hat_j, err := receiver.curve.Scalar.SetBytes(receiver.OutExtPackChoices[j*sBytes : (j+1)*sBytes])
		if err != nil {
			return nil, errs.WrapFailed(err, "OutExtPackChoices scalar from bytes for SoftSpoken COTe check")
		}
		Chi_j, err := receiver.curve.Scalar.SetBytes(round2Output.Chi[j][j*sBytes : (j+1)*sBytes])
		if err != nil {
			return nil, errs.WrapFailed(err, "Chi scalar from bytes for SoftSpoken COTe check")
		}
		round3Output.x_check = round3Output.x_check.Add(Chi_j.Mul(x_hat_j))
	}
	// 		t^i = ...
	for i := 0; i < Kappa; i++ {
		//         ... t^i_hat_{m+1} ...
		round3Output.t_check[i], err = receiver.curve.Scalar.SetBytes(receiver.ExpOTeResults[0][i][LBytes : LBytes+sBytes])
		if err != nil {
			return nil, errs.WrapFailed(err, "Last ExpOTeResults scalar from bytes for SoftSpoken COTe check")
		}
		//                           ... + Σ{j=0}^{m-1} \chi_j • t^i_hat_j
		for j := 0; j < m; j++ {
			t_hat_j, err := receiver.curve.Scalar.SetBytes(receiver.ExpOTeResults[0][i][j*sBytes : (j+1)*sBytes])
			if err != nil {
				return nil, errs.WrapFailed(err, "ExpOTeResults scalar from bytes for SoftSpoken COTe check")
			}
			Chi_j, err := receiver.curve.Scalar.SetBytes(round2Output.Chi[j][j*sBytes : (j+1)*sBytes]) // TODO: put in a single loop over j \in [0, m] with x_check
			if err != nil {
				return nil, errs.WrapFailed(err, "Chi scalar from bytes for SoftSpoken COTe check")
			}
			round3Output.t_check[i] = round3Output.t_check[i].Add(Chi_j.Mul(t_hat_j))
		}
	}
	return round3Output, nil
}

// Round4CheckConsistency checks the consistency using the challenge response.
func (sender *Sender) Round4CheckConsistency(round2Output *Round2Output, round3Output *Round3Output) error {
	// (C.3) Check the consistency of the challenge response computing q^i
	for i := 0; i < Kappa; i++ {
		// q^i = q^i_hat_{m+1} ...
		q_check, err := sender.curve.Scalar.SetBytes(sender.extCorrelations[i][LBytes : LBytes+sBytes])
		if err != nil {
			return errs.WrapFailed(err, "Last extCorrelations scalar from bytes for SoftSpoken COTe check")
		}
		//         ... + Σ{j=0}^{m-1} \chi_j • q^i_hat_j
		for j := 0; j < m; j++ {
			q_hat_j, err := sender.curve.Scalar.SetBytes(sender.extCorrelations[i][j*sBytes : (j+1)*sBytes])
			if err != nil {
				return errs.WrapFailed(err, "extCorrelations scalar from bytes for SoftSpoken COTe check")
			}
			Chi_j, err := sender.curve.Scalar.SetBytes(round2Output.Chi[j][j*sBytes : (j+1)*sBytes])
			if err != nil {
				return errs.WrapFailed(err, "Chi scalar from bytes for SoftSpoken COTe check")
			}
			q_check = q_check.Add(Chi_j.Mul(q_hat_j))
		}
		//  and checking q^i = t^i + \Delta_i • x \forall i \in [kappa]. If not, abort. //TODO, unpack bit to use individually.
		Delta_i, err := sender.curve.Scalar.SetBytes(sender.baseOtRecOutputs.PackedRandomChoiceBits[i : i+1])
		if err != nil {
			return errs.WrapFailed(err, "Delta scalar from bytes for SoftSpoken COTe check")
		}
		q_expected := round3Output.t_check[i].Add(Delta_i.Mul(round3Output.x_check))
		if !q_check.Sub(q_expected).IsZero() {
			return errs.NewIdentifiableAbort("q_check != q_expected")
		}
	}
	return nil
}
