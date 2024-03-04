package ot

import (
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/ct"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const (
	// Kappa (κ) is the security parameter of the OT protocols.
	Kappa      = base.CollisionResistance
	KappaBytes = base.CollisionResistanceBytes
)

var HashFunction = base.RandomOracleHashFunction // Output length must be >= KappaBytes

type (
	ChoiceBits []byte // Choice (x) are the "packed" choice bits.

	MessageElement = [KappaBytes]byte // [κ]bits, κ-bit chunks of the ROT/OT message.
	Message        = []MessageElement // [L][κ]bits, the messages in ROT/OT.
	MessagePair    = [2]Message       // [2][L][κ]bits, the 2 sender messages in ROT/OT.
	ChosenMessage  = Message          // [L][κ]bits, the receiver's chosen message in ROT/OT.

	CorrelatedElement = curves.Scalar       // ℤq, each element of the COT message.
	CorrelatedMessage = []CorrelatedElement // [L]ℤq, (a, Z_A, z_B) are the L-scalar messages in COT.
)

func (c ChoiceBits) Select(i int) byte {
	return bitstring.SelectBit(c, i)
}

// Participant contains the common members of the sender and receiver.
type Participant struct {
	Xi int // ξ, the number of OTs that are run in parallel.
	L  int // L, the number of elements in each OT message.

	Curve      curves.Curve
	SessionId  []byte
	Transcript transcripts.Transcript
	Csprng     io.Reader

	_ ds.Incomparable
}

func NewParticipant(Xi, L int, curve curves.Curve, sessionId []byte, label string, transcript transcripts.Transcript, csprng io.Reader) (*Participant, error) {
	if err := validateInputs(Xi, L, sessionId, csprng); err != nil {
		return nil, errs.WrapArgument(err, "couldn't construct ot participant")
	}
	dst := fmt.Sprintf("%s_%d_%d_%s", label, Xi, L, curve.Name())
	transcript, sessionId, err := hagrid.InitialiseProtocol(transcript, sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}
	return &Participant{
		Curve:      curve,
		Xi:         Xi,
		L:          L,
		SessionId:  sessionId,
		Transcript: transcript,
		Csprng:     csprng,
	}, nil
}

func validateInputs(Xi, L int, sessionId []byte, csprng io.Reader) error {
	if Xi&0x07 != 0 || Xi < 1 { // `Enforce batchSize % 8 != 0`
		return errs.NewValue("batch size should be a positive multiple of 8")
	}
	if L < 1 {
		return errs.NewValue("message length should be positive")
	}
	if csprng == nil {
		return errs.NewIsNil("prng is nil")
	}
	if len(sessionId) == 0 {
		return errs.NewIsNil("unique session id is empty")
	}
	return nil
}

/*.-------------------- RANDOM OBLIVIOUS TRANSFER (ROT) ---------------------.*/

// SenderRotOutput are the outputs that the sender will obtain as a result of running a Random OT (ROT) protocol.
type SenderRotOutput struct {
	Messages []MessagePair // Messages (s_0, s_1) are the sender's messages.
	_        ds.Incomparable
}

// ReceiverRotOutput are the outputs that the receiver will obtain as a result of running a Random OT (ROT) protocol.
type ReceiverRotOutput struct {
	Choices        ChoiceBits      // Choices (x) is the batch of "packed" choice bits of the receiver.
	ChosenMessages []ChosenMessage // ChosenMessages (r_x) is the batch of messages chosen by receiver.

	_ ds.Incomparable
}

/*.------------------- (standard) OBLIVIOUS TRANSFER (OT) -------------------.*/

type OneTimePadedMaskPair = MessagePair // OneTimePadedMaskPair are the two masks used to turn a ROT into a standard OT.

// Encrypt allows a ROT (Random OT) sender to encrypt messages with one-time pad.
// It converts the ROT into a standard chosen-message OT, both for base OTs and OT extensions.
func (sROT *SenderRotOutput) Encrypt(OTmessagePairs []MessagePair) (masks []OneTimePadedMaskPair, err error) {
	Xi := len(sROT.Messages)
	L := len(sROT.Messages[0][0])
	if len(OTmessagePairs) != Xi {
		return nil, errs.NewArgument("number of OT message pairs should be Xi (%d != %d)", len(OTmessagePairs), Xi)
	}
	masks = make([]OneTimePadedMaskPair, Xi)
	for j := 0; j < Xi; j++ {
		if len(OTmessagePairs[j][0]) != L || len(OTmessagePairs[j][1]) != L {
			return nil, errs.NewArgument("OT message[%d] length should be L (%d != %d || %d != %d )",
				j, len(OTmessagePairs[j][0]), L, len(OTmessagePairs[j][1]), L)
		}
		masks[j][0] = make([]MessageElement, L)
		masks[j][1] = make([]MessageElement, L)
		for l := 0; l < L; l++ {
			subtle.XORBytes(masks[j][0][l][:], sROT.Messages[j][0][l][:], OTmessagePairs[j][0][l][:])
			subtle.XORBytes(masks[j][1][l][:], sROT.Messages[j][1][l][:], OTmessagePairs[j][1][l][:])
		}
	}
	return masks, nil
}

// Decrypt allows a ROT (Random OT) receiver to decrypt messages with one-time pad.
// It converts the ROT into a standard chosen-message OT, both for base OTs and OT extensions.
func (rROT *ReceiverRotOutput) Decrypt(masks []OneTimePadedMaskPair) (OTchosenMessages []ChosenMessage, err error) {
	Xi := len(rROT.ChosenMessages)
	L := len(rROT.ChosenMessages[0])
	if len(masks) != Xi {
		return nil, errs.NewArgument("number of masks should be Xi (%d != %d)", len(masks), Xi)
	}
	OTchosenMessages = make([]ChosenMessage, Xi)
	var mask MessageElement
	for j := 0; j < Xi; j++ {
		if len(masks[j][0]) != L || len(masks[j][1]) != L {
			return nil, errs.NewArgument("mask[%d] length should be L (%d != %d)", j, len(masks[j][0]), L)
		}
		OTchosenMessages[j] = make(ChosenMessage, L)
		choice := int(rROT.Choices.Select(j))
		for l := 0; l < L; l++ {
			ct.SelectSlice(choice, mask[:], masks[j][0][l][:], masks[j][1][l][:])
			subtle.XORBytes(OTchosenMessages[j][l][:], rROT.ChosenMessages[j][l][:], masks[j][choice][l][:])
		}
	}
	return OTchosenMessages, nil
}

/*.------------------ CORRELATED OBLIVIOUS TRANSFER (COT) -------------------.*/

type CorrelationMask = CorrelatedMessage // Tau (τ) is the correlation mask of the sender, used to turn a ROT into a COT.

// CreateCorrelation allows a ROT receiver to input `a` and establish a
// correlation `a*x = z_A + z_B`, converting the ROT into a Correlated OT (COT).
// It generates the correlation mask `τ` to be sent to the receiver, and z_A.
func (sROT *SenderRotOutput) CreateCorrelation(a []CorrelatedMessage) (z_A []CorrelatedMessage, tau []CorrelationMask, err error) {
	Xi := len(sROT.Messages)
	L := len(sROT.Messages[0][0])
	if len(a) != Xi {
		return nil, nil, errs.NewArgument("senderInput size should be same as batch size (%d != %d)", len(a), Xi)
	}
	scalarField := a[0][0].ScalarField()
	z_A = make([]CorrelatedMessage, Xi)
	tau = make([]CorrelationMask, Xi)

	for j := 0; j < Xi; j++ {
		if len(a[j]) != L {
			return nil, nil, errs.NewArgument("a[%d] length should be L (%d != %d)", j, len(a[j]), L)
		}
		z_A[j] = make(CorrelatedMessage, L)
		tau[j] = make(CorrelatedMessage, L)
		for l := 0; l < L; l++ {
			// z_A_j = ECS(s_0_j)
			if z_A[j][l], err = scalarField.Hash(sROT.Messages[j][0][l][:]); err != nil {
				return nil, nil, errs.WrapHashing(err, "bad hashing s_0_j to scalar for ROT->COT")
			}
			// τ_j = ECS(s_1_j) - z_A_j + α_j
			if tau[j][l], err = scalarField.Hash(sROT.Messages[j][1][l][:]); err != nil {
				return nil, nil, errs.WrapHashing(err, "bad hashing s_1_j to scalar for ROT->COT")
			}
			tau[j][l] = tau[j][l].Sub(z_A[j][l]).Add(a[j][l])
		}
	}
	return z_A, tau, nil
}

// ApplyCorrelation allows a ROT receiver to correlate `a*x = z_A + z_B` with
// his bit x of the ROT and the sender's `a` and `z_A`, obtaining `z_B`.
// It turns the ROT into a COT.
func (rROT *ReceiverRotOutput) ApplyCorrelation(tau []CorrelationMask) (z_B []CorrelatedMessage, err error) {
	Xi := len(rROT.ChosenMessages)
	L := len(rROT.ChosenMessages[0])
	if len(tau) != Xi {
		return nil, errs.NewArgument("length of tau should be same as batch size (%d != %d)",
			len(tau), Xi)
	}
	scalarField := tau[0][0].ScalarField()
	z_B = make([]CorrelatedMessage, Xi)
	for j := 0; j < Xi; j++ {
		if len(tau[j]) != L {
			return nil, errs.NewArgument("tau[%d] length should be L (%d != %d)", j, len(tau[j]), L)
		}
		z_B[j] = make(CorrelatedMessage, L)
		for l := 0; l < L; l++ {
			r_x, err := scalarField.Hash(rROT.ChosenMessages[j][l][:])
			if err != nil {
				return nil, errs.WrapHashing(err, "bad hashing r_x_j to scalar for ROT -> COT")
			}
			r_x = r_x.Neg()
			bit := rROT.Choices.Select(j) != 0
			// z_B_j = τ_j - ECS(r_x_j)  if x_j == 1
			//       =     - ECS(r_x_j)  if x_j == 0
			z_B[j][l] = scalarField.Select(bit, r_x, tau[j][l].Add(r_x))
		}
	}
	return z_B, nil
}
