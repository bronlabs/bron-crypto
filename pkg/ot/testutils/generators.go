package ot_testutils

import (
	crand "crypto/rand"
	"fmt"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/testutils/property"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	"golang.org/x/crypto/sha3"
	"pgregory.net/rapid"
)

/*.------------------------------- PARAMETERS -------------------------------.*/

var _ testutils.PublicParams[*OtParams] = (*OtParams)(nil)
var _ testutils.UnhappyParams[*OtParams] = (*OtParams)(nil)

type OtParams struct {
	Xi           int
	L            int
	Curve        curves.Curve
	SessionId    []byte
	MayBeInvalid bool
}

func (pp *OtParams) Seed() []byte {
	return pp.SessionId
}

func (pp *OtParams) Name() string {
	return "Mismatched OT parameters"
}

func (pp *OtParams) String() string {
	return fmt.Sprintf("Xi:%d, L:%d, Curve:%s, SessionId:%x", pp.Xi, pp.L, pp.Curve, pp.SessionId)
}

func (pp *OtParams) AreValid() bool {
	return (pp.Xi > 0) && (pp.Xi%128 == 0) &&
		pp.L > 0 &&
		pp.Curve != nil &&
		len(pp.SessionId) > 0
}

func (pp *OtParams) CanBeInvalid() bool {
	return pp.MayBeInvalid
}

func (pp *OtParams) GeneratorPublicParams() *rapid.Generator[testutils.PublicParams[*OtParams]] {
	return rapid.Custom(func(t *rapid.T) testutils.PublicParams[*OtParams] {
		return &OtParams{
			Xi:           rapid.IntRange(1, 2).Draw(t, "Xi") * 128,
			L:            rapid.IntRange(1, 10).Draw(t, "L"),
			Curve:        property.NonPairingCurveGen.Draw(t, "Curve"),
			SessionId:    property.SessionIdGen.Draw(t, "SessionId"),
			MayBeInvalid: false,
		}
	})
}

func (pp *OtParams) GeneratorUnhappyParams() *rapid.Generator[testutils.UnhappyParams[*OtParams]] {
	return rapid.Custom(func(t *rapid.T) testutils.UnhappyParams[*OtParams] {
		return &OtParams{
			Xi:           rapid.IntRange(1, 2).Draw(t, "Xi") * 128,
			L:            rapid.IntRange(1, 10).Draw(t, "L"),
			Curve:        property.NonPairingCurveGen.Draw(t, "Curve"),
			SessionId:    property.SessionIdGen.Draw(t, "SessionId"),
			MayBeInvalid: false,
		}
	})
}

var _ (testutils.UnhappyParams[*ReuseParams]) = (*ReuseParams)(nil)

// ReuseParams are used to specify the round to reuse in the second run of a protocol in an UnhappyPath.
type ReuseParams struct {
	ReuseRound uint
}

func (rp *ReuseParams) Name() string {
	return "ReuseRoundMessages"
}

func (rp *ReuseParams) AreValid() bool {
	return true
}

func (rp *ReuseParams) CanBeInvalid() bool {
	return false
}

func (rp *ReuseParams) String() string {
	return fmt.Sprintf("ReuseRound:%d", rp.ReuseRound)
}

func (rp *ReuseParams) GeneratorUnhappyParams() *rapid.Generator[testutils.UnhappyParams[*ReuseParams]] {
	return rapid.Custom(func(t *rapid.T) testutils.UnhappyParams[*ReuseParams] {
		return &ReuseParams{
			ReuseRound: rapid.UintRange(1, 3).Draw(t, "ReuseRound"),
		}
	})
}

/*.-------------------------------- SCENARIO --------------------------------.*/

type OtScenario struct {
	SenderKey   types.AuthKey
	ReceiverKey types.AuthKey
}

// GenerateScenario generates sender and receiver identities for OTs.
func GenerateScenario() (scenario *OtScenario, err error) {
	cipherSuite, err := ttu.MakeSignatureProtocol(k256.NewCurve(), sha3.New256)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not make signature protocol for OT identities")
	}
	authKeys, err := ttu.MakeTestAuthKeys(cipherSuite, 2)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not make test auth keys for OT identities")
	}
	return &OtScenario{SenderKey: authKeys[0], ReceiverKey: authKeys[1]}, nil
}

/*.--------------------------------- INPUTS ---------------------------------.*/

// GenerateInputsROT generates random inputs for (Randomised / standard) OTs.
func GenerateInputsROT(Xi, L int) (
	receiverChoiceBits ot.PackedBits, // receiver's input, the Choice bits x
	err error,
) {
	if L < 1 || Xi < 1 || Xi%8 != 0 {
		return nil, errs.NewLength(" cannot generate random inputs for L=%d, Xi=%d", L, Xi)
	}
	receiverChoiceBits = make(ot.PackedBits, Xi/8)
	if _, err := crand.Read(receiverChoiceBits); err != nil {
		return nil, errs.WrapRandomSample(err, "could not generate random choice bits")
	}
	return receiverChoiceBits, nil
}

// GenerateInputsOT generates random inputs for (Randomised / standard) OTs.
func GenerateInputsOT(Xi, L int) (
	receiverChoiceBits ot.PackedBits, // receiver's input, the Choice bits x
	senderMessages [][2]ot.Message, // sender's input in OT, the MessagePair (s_0, s_1)
	err error,
) {
	if L < 1 || Xi < 1 || Xi%8 != 0 {
		return nil, nil, errs.NewLength(" cannot generate random inputs for L=%d, Xi=%d", L, Xi)
	}
	receiverChoiceBits = make(ot.PackedBits, Xi/8)
	if _, err := crand.Read(receiverChoiceBits); err != nil {
		return nil, nil, errs.WrapRandomSample(err, "could not generate random choice bits")
	}
	senderMessages = make([][2]ot.Message, Xi)
	for i := 0; i < Xi; i++ {
		senderMessages[i] = [2]ot.Message{make(ot.Message, L), make(ot.Message, L)}
		for l := 0; l < L; l++ {
			_, err0 := crand.Read(senderMessages[i][0][l][:])
			_, err1 := crand.Read(senderMessages[i][1][l][:])
			if err0 != nil || err1 != nil {
				return nil, nil, errs.WrapRandomSample(err, "could not generate random message")
			}
		}
	}
	return receiverChoiceBits, senderMessages, nil
}

// GenerateInputsCOT generates random inputs for Correlated OTs.
func GenerateInputsCOT(Xi, L int, curve curves.Curve) (
	receiverChoiceBits ot.PackedBits, // receiver's input, the Choice bits (x)
	senderInput []ot.CorrelatedMessage, // sender's input, the CorrelatedMessage (α)
	err error,
) {
	if L < 1 || Xi < 1 || Xi%8 != 0 {
		return nil, nil, errs.NewLength(" cannot generate random inputs for L=%d, Xi=%d", L, Xi)
	}
	receiverChoiceBits = make(ot.PackedBits, Xi/8)
	if _, err := crand.Read(receiverChoiceBits); err != nil {
		return nil, nil, errs.WrapRandomSample(err, "could not generate random choice bits")
	}
	if curve == nil { // Just need the input choices
		return receiverChoiceBits, nil, nil
	}
	senderInput = make([]ot.CorrelatedMessage, Xi)
	for j := 0; j < Xi; j++ {
		senderInput[j] = make(ot.CorrelatedMessage, L)
		for l := 0; l < L; l++ {
			senderInput[j][l], err = curve.Scalar().ScalarField().Random(crand.Reader)
			if err != nil {
				return nil, nil, errs.WrapRandomSample(err, "could not generate random scalar")
			}
		}
	}
	return receiverChoiceBits, senderInput, nil
}
