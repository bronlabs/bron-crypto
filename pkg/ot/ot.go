package ot

import (
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/bronlabs/krypton-primitives/pkg/base"
	"github.com/bronlabs/krypton-primitives/pkg/base/ct"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts/hagrid"
)

const (
	// Kappa (κ) is the security parameter of the OT protocols.
	Kappa      = base.ComputationalSecurity
	KappaBytes = Kappa / 8
)

var HashFunction = base.RandomOracleHashFunction // Output length must be >= KappaBytes

type Protocol struct {
	types.Protocol
	L  int // L, the number of elements in each OT message.
	Xi int // ξ, the number of OTs that are run in parallel.
}

// Participant contains the common members of the sender and receiver.
type Participant struct {
	myAuthKey  types.AuthKey
	Prng       io.Reader
	Protocol   *Protocol
	Round      int
	SessionId  []byte
	Transcript transcripts.Transcript

	_ ds.Incomparable
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.myAuthKey
}

func (p *Participant) OtherParty() types.IdentityKey {
	parties := p.Protocol.Participants().List()
	if !parties[0].Equal(p.myAuthKey) {
		return parties[0]
	}
	return parties[1]
}

func NewParticipant(myAuthKey types.AuthKey, protocol types.Protocol, Xi, L int, sessionId []byte, label string, transcript transcripts.Transcript, prng io.Reader, initialRound int) (*Participant, error) {
	if err := validateInputs(myAuthKey, protocol, Xi, L, sessionId, prng); err != nil {
		return nil, errs.WrapArgument(err, "couldn't construct ot participant")
	}
	dst := fmt.Sprintf("%s_%d_%d_%s", label, Xi, L, protocol.Curve().Name())
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, prng)
	}
	boundSessionId, err := transcript.Bind(sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}
	participant := &Participant{
		myAuthKey:  myAuthKey,
		Prng:       prng,
		Protocol:   &Protocol{Protocol: protocol, L: L, Xi: Xi},
		SessionId:  boundSessionId,
		Round:      initialRound,
		Transcript: transcript,
	}
	if err := types.ValidateProtocol(participant, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct ot participant")
	}
	return participant, nil
}

func validateInputs(myAuthKey types.AuthKey, protocol types.Protocol, Xi, L int, sessionId []byte, csprng io.Reader) error {
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
	if err := types.ValidateAuthKey(myAuthKey); err != nil {
		return errs.WrapValidation(err, "my auth key")
	}
	if err := types.ValidateProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config")
	}
	if protocol.Participants().Size() != 2 {
		return errs.NewSize("#participants (=%d) != 2", protocol.Participants().Size())
	}
	return nil
}

/*.-------------------- RANDOM OBLIVIOUS TRANSFER (ROT) ---------------------.*/

// SenderRotOutput are the outputs that the sender will obtain as a result of running a Random OT (ROT) protocol.
type SenderRotOutput struct {
	MessagePairs [][2]Message // Messages (s_0, s_1) are the sender's messages.
	_            ds.Incomparable
}

// ReceiverRotOutput are the outputs that the receiver will obtain as a result of running a Random OT (ROT) protocol.
type ReceiverRotOutput struct {
	Choices        PackedBits // Choices (x) is the batch of "packed" choice bits of the receiver.
	ChosenMessages []Message  // ChosenMessages (r_x) is the batch of messages chosen by receiver.

	_ ds.Incomparable
}

/*.------------------- (standard) OBLIVIOUS TRANSFER (OT) -------------------.*/

type OneTimePadedMaskPair = [2]Message // OneTimePadedMaskPair are the two masks used to turn a ROT into a standard OT.

// Encrypt allows a ROT (Random OT) sender to encrypt messages with one-time pad.
// It converts the ROT into a standard chosen-message OT, both for base OTs and OT extensions.
func (sROT *SenderRotOutput) Encrypt(otMessagePairs [][2]Message) (masks []OneTimePadedMaskPair, err error) {
	Xi := len(sROT.MessagePairs)
	L := len(sROT.MessagePairs[0][0])
	if len(otMessagePairs) != Xi {
		return nil, errs.NewArgument("number of OT message pairs should be Xi (%d != %d)", len(otMessagePairs), Xi)
	}
	masks = make([]OneTimePadedMaskPair, Xi)
	for j := 0; j < Xi; j++ {
		if len(otMessagePairs[j][0]) != L || len(otMessagePairs[j][1]) != L {
			return nil, errs.NewArgument("OT message[%d] length should be L (%d != %d || %d != %d )",
				j, len(otMessagePairs[j][0]), L, len(otMessagePairs[j][1]), L)
		}
		masks[j][0] = make([]MessageElement, L)
		masks[j][1] = make([]MessageElement, L)
		for l := 0; l < L; l++ {
			subtle.XORBytes(masks[j][0][l][:], sROT.MessagePairs[j][0][l][:], otMessagePairs[j][0][l][:])
			subtle.XORBytes(masks[j][1][l][:], sROT.MessagePairs[j][1][l][:], otMessagePairs[j][1][l][:])
		}
	}
	return masks, nil
}

// Decrypt allows a ROT (Random OT) receiver to decrypt messages with one-time pad.
// It converts the ROT into a standard chosen-message OT, both for base OTs and OT extensions.
func (rROT *ReceiverRotOutput) Decrypt(masks []OneTimePadedMaskPair) (OTchosenMessages []Message, err error) {
	Xi := len(rROT.ChosenMessages)
	L := len(rROT.ChosenMessages[0])
	if len(masks) != Xi {
		return nil, errs.NewArgument("number of masks should be Xi (%d != %d)", len(masks), Xi)
	}
	OTchosenMessages = make([]Message, Xi)
	var mask MessageElement
	for j := 0; j < Xi; j++ {
		if len(masks[j][0]) != L || len(masks[j][1]) != L {
			return nil, errs.NewArgument("mask[%d] length should be L (%d != %d)", j, len(masks[j][0]), L)
		}
		OTchosenMessages[j] = make(Message, L)
		choice := uint64(rROT.Choices.Get(uint(j)))
		for l := 0; l < L; l++ {
			ct.SliceSelect(choice, mask[:], masks[j][0][l][:], masks[j][1][l][:])
			subtle.XORBytes(OTchosenMessages[j][l][:], rROT.ChosenMessages[j][l][:], mask[:])
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
	Xi := len(sROT.MessagePairs)
	L := len(sROT.MessagePairs[0][0])
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
			if z_A[j][l], err = scalarField.Hash(sROT.MessagePairs[j][0][l][:]); err != nil {
				return nil, nil, errs.WrapHashing(err, "bad hashing s_0_j to scalar for ROT->COT")
			}
			// τ_j = ECS(s_1_j) - z_A_j + α_j
			if tau[j][l], err = scalarField.Hash(sROT.MessagePairs[j][1][l][:]); err != nil {
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
			bit := uint64(rROT.Choices.Get(uint(j)))
			// z_B_j = τ_j - ECS(r_x_j)  if x_j == 1
			//       =     - ECS(r_x_j)  if x_j == 0
			z_B[j][l] = scalarField.Select(bit, r_x, tau[j][l].Add(r_x))
		}
	}
	return z_B, nil
}
