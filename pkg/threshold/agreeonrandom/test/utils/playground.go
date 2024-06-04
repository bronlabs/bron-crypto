package agreeonrandom_testutils

import (
	"fmt"
	"io"
	"reflect"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom"
	"golang.org/x/crypto/sha3"
)

type ProtocolRunner[PublicParam types.Protocol, Participant any, Input any, Output any] interface {
	// CreateParties creates an MPC scenario with enough parties to run the protocol.
	// These parties can be shared across multiple protocol runs, typically by
	// selecting a subset of them for each run.
	CreateParties(numberOfParties int) (scenario []types.AuthKey, err error)
	// CreateParticipants initializes the participants for a protocol run. The
	// PublicParam contains the list of parties from the scenario that will be
	// used in this run. It runs any necessary setup for the protocol.
	CreateParticipants(parties []types.AuthKey, pp PublicParam) ([]Participant, error)
	// RunProtocol runs the protocol among the selected participants. It returns
	// the result of the protocol run, containing both generated inputs and the
	// required outputs.
	RunProtocol(p []Participant) (Input, Output, error)
}

type NoneT struct{}

func IsNoneT[T any]() bool {
	NoneType := reflect.TypeFor[NoneT]()
	TestedType := reflect.TypeFor[T]()
	return NoneType == TestedType
}

// type M[P types.Protocol] network.Message[P]
// type Ms[P types.Protocol] network.RoundMessages[P, M[P]]

type Round[
	InB any, OutB any, // Broadcast round messages
	InP2P any, OutP2P any, // Peer-to-Peer messages
	InP any, OutP any, // Protocol results
] struct {
	Number          int
	InputBroadcast  InB
	OutputBroadcast OutB
	InputP2P        InP2P
	OutputP2P       OutP2P
	InputProtocol   InP
	OutputProtocol  OutP
	Error           error
}

func (r *Round[InB, OutB, InP2P, OutP2P, InP, OutP]) Run(participant any, roundNumber int) (err error) {
	// // Capture panics
	// defer func(err *error) {
	// 	if r := recover(); r != nil {
	// 		if err == nil {
	// 			*err = errs.NewFailed("Could not run generic round function")
	// 		} else {
	// 			*err = errs.WrapFailed(*err, "Could not run generic round function")
	// 		}
	// 	}
	// }(&err)

	// Validate round function
	abstractParticipant := reflect.ValueOf(participant)
	roundName := fmt.Sprintf("Round%d", roundNumber)
	f := abstractParticipant.MethodByName(roundName)
	if !f.IsValid() {
		return errs.NewMissing("%s method not found", roundName)
	}
	if f.Kind() != reflect.Func {
		return errs.NewType("roundFunc must be a function")
	}
	if f.Type().NumIn() > 4 {
		return errs.NewType("roundFunc must have at most 4 input arguments (receiver, broadcast, P2P, protocolIns)")
	}
	if f.Type().NumOut() > 4 {
		return errs.NewType("roundFunc must have at most 4 output arguments (broadcast, P2P, protocolOuts, error)")
	}

	// Prepare inputs
	ins := make([]reflect.Value, 0, f.Type().NumIn())
	if !IsNoneT[InB]() {
		ins = append(ins, reflect.ValueOf(r.InputBroadcast))
	}
	if !IsNoneT[InP2P]() {
		ins = append(ins, reflect.ValueOf(r.InputP2P))
	}
	if !IsNoneT[InP]() {
		ins = append(ins, reflect.ValueOf(r.InputProtocol))
	}

	// Run function
	if len(ins) != f.Type().NumIn() {
		return errs.NewArgument("Invalid number of arguments (expected %d, got %d)", f.Type().NumIn(), len(ins))
	}
	outs := f.Call(ins)

	// Extract outputs
	var ok bool
	for i, out := range outs {
		switch {
		case utils.IsNil(r.OutputBroadcast) && !IsNoneT[OutB]():
			if r.OutputBroadcast, ok = out.Interface().(OutB); !ok {
				return errs.NewMissing("Could not cast output %d to broadcast output", i)
			}
		case utils.IsNil(r.OutputP2P) && !IsNoneT[OutP2P]():
			if r.OutputP2P, ok = out.Interface().(OutP2P); !ok {
				return errs.NewMissing("Could not cast output %d to P2P output", i)
			}
		case utils.IsNil(r.OutputProtocol) && !IsNoneT[OutP]():
			if r.OutputProtocol, ok = out.Interface().(OutP); !ok {
				return errs.NewMissing("Could not cast output %d to protocol output", i)
			}
		case out.Type().Implements(reflect.TypeFor[error]()):
			if err, ok := out.Interface().(error); ok && err != nil {
				r.Error = err
			}
		default:
			return errs.NewType("Unrecognised type (%s) for output %d", out.Type().Name(), i)
		}
	}
	return nil
}

func RunAnyProtocol() {
	// Create Scenario: contains enough parties to run the protocol (MakeTestAuthKeys). Shared across all tests.

	// Create ProtocolParams: contains the public parametrization of the protocol, but only things that won't change across several protocol runs. e.g. curve, participants. MUST BE SERIALIZABLE.

	// Create Protocol Participants: contains Round, Transcript, State, Prng

	// Run Protocol
}

// @Alireza: observations:
//  - Round names will all be the same, can we use that to our advantage?
//  - Be careful on protocols with several types of participants.
//  - Take a look at state machine examples (Java, Javascript, any other), it might inspire us.

type AgreeOnRandomProtocolRunner struct {
}

var DefaultSigningCurve = edwards25519.NewCurve()
var DefaultHashFunction = sha3.New256

func CreateNPartyScenario(numberOfParties int) (nPartyScenario []types.AuthKey, err error) {
	cipherSuite, err := ttu.MakeSignatureProtocol(DefaultSigningCurve, DefaultHashFunction)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not make signing suite")
	}
	nPartyScenario, err = ttu.MakeTestAuthKeys(cipherSuite, numberOfParties)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not make test auth keys for OT identities")
	}
	return nPartyScenario, nil
}

func (a *AgreeOnRandomProtocolRunner) CreateParties(n int) (nParties []types.AuthKey, err error) {
	cipherSuite, err := ttu.MakeSignatureProtocol(DefaultSigningCurve, DefaultHashFunction)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not make signing suite")
	}
	nParties, err = ttu.MakeTestAuthKeys(cipherSuite, n)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not make test auth keys for OT identities")
	}
	return nParties, nil
}

func CreateParticipants(parties []types.AuthKey, pp types.Protocol, prng io.Reader) ([]*agreeonrandom.Participant, error) {
	participants := make([]*agreeonrandom.Participant, 0, len(parties))
	for i := range parties {
		participant, err := agreeonrandom.NewParticipant(parties[i], pp, nil, prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct participant")
		}
		participants = append(participants, participant)
	}
	return participants, nil
}

type Round1Runner = Round[
	NoneT, *agreeonrandom.Round1Broadcast,
	NoneT, NoneT,
	NoneT, NoneT]

type Round2Runner = Round[
	network.RoundMessages[types.Protocol, *agreeonrandom.Round1Broadcast], *agreeonrandom.Round2Broadcast,
	NoneT, NoneT,
	NoneT, NoneT]

type Round3Runner = Round[
	network.RoundMessages[types.Protocol, *agreeonrandom.Round2Broadcast], NoneT,
	NoneT, NoneT,
	NoneT, []byte]

func (a *AgreeOnRandomProtocolRunner) RunProtocol(participants []*agreeonrandom.Participant) (randomValues [][]byte, err error) {

	r1Out := make([]*agreeonrandom.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1Runner := Round1Runner{}
		if err = round1Runner.Run(participant, 1); err != nil {
			return nil, errs.WrapRound(err, "RoundRunner could not run Round 1")
		}
		if round1Runner.Error != nil {
			return nil, errs.WrapFailed(round1Runner.Error, "Round 1 run failed")
		}
		r1Out[i] = round1Runner.OutputBroadcast
	}
	r2In := ttu.MapBroadcastO2I(participants, r1Out)

	r2Out := make([]*agreeonrandom.Round2Broadcast, len(participants))
	for i, participant := range participants {
		round2Runner := Round2Runner{
			InputBroadcast: r2In[i],
		}
		if err = round2Runner.Run(participant, 2); err != nil {
			return nil, errs.WrapRound(err, "RoundRunner could not run Round 2")
		}
		if round2Runner.Error != nil {
			return nil, errs.WrapFailed(round2Runner.Error, "Round 2 run failed")
		}
		r2Out[i] = round2Runner.OutputBroadcast
	}
	r3In := ttu.MapBroadcastO2I(participants, r2Out)

	protocolOut := make([][]byte, len(participants))
	for i, participant := range participants {
		round3Runner := Round3Runner{
			InputBroadcast: r3In[i],
		}
		if err = round3Runner.Run(participant, 3); err != nil {
			return nil, errs.WrapRound(err, "RoundRunner could not run Round 3")
		}
		if round3Runner.Error != nil {
			return nil, errs.WrapFailed(round3Runner.Error, "Round 3 run failed")
		}
		protocolOut[i] = round3Runner.OutputProtocol
	}
	return protocolOut, nil
}

func RunAgreeOnRandom(curve curves.Curve, identities []types.IdentityKey, prng io.Reader) ([]byte, error) {
	participants := make([]*agreeonrandom.Participant, 0, len(identities))
	set := hashset.NewHashableHashSet(identities...)
	protocol, err := ttu.MakeProtocol(curve, identities)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't make protocol")
	}
	for iterator := set.Iterator(); iterator.HasNext(); {
		identity := iterator.Next()
		participant, err := agreeonrandom.NewParticipant(identity.(types.AuthKey), protocol, nil, prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct participant")
		}
		participants = append(participants, participant)
	}

	r1Out, err := DoRound1(participants)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not execute round 1")
	}
	r2In := ttu.MapBroadcastO2I(participants, r1Out)
	r2Out, err := DoRound2(participants, r2In)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not execute round 2")
	}
	r3In := ttu.MapBroadcastO2I(participants, r2Out)
	agreeOnRandoms, err := DoRound3(participants, r3In)

	if err != nil {
		return nil, errs.WrapFailed(err, "could not execute round 3")
	}
	if len(agreeOnRandoms) != set.Size() {
		return nil, errs.NewArgument("expected %d agreeOnRandoms, got %d", len(identities), len(agreeOnRandoms))
	}

	// check all values in agreeOnRandoms the same
	for j := 1; j < len(agreeOnRandoms); j++ {
		if len(agreeOnRandoms[0]) != len(agreeOnRandoms[j]) {
			return nil, errs.NewLength("slices are not equal")
		}

		for i := range agreeOnRandoms[0] {
			if agreeOnRandoms[0][i] != agreeOnRandoms[j][i] {
				return nil, errs.NewLength("slices are not equal")
			}
		}
	}

	return agreeOnRandoms[0], nil
}

func DoRound1(participants []*agreeonrandom.Participant) (round1Outputs []*agreeonrandom.Round1Broadcast, err error) {
	round1Outputs = make([]*agreeonrandom.Round1Broadcast, len(participants))
	for i, participant := range participants {
		round1Outputs[i], err = participant.Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "could not execute round 1 for participant %d", i)
		}
	}
	return round1Outputs, nil
}

func DoRound2(participants []*agreeonrandom.Participant, round2Inputs []network.RoundMessages[types.Protocol, *agreeonrandom.Round1Broadcast]) (round2Outputs []*agreeonrandom.Round2Broadcast, err error) {
	round2Outputs = make([]*agreeonrandom.Round2Broadcast, len(participants))
	for i, participant := range participants {
		round2Outputs[i], err = participant.Round2(round2Inputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not execute round 2 for participant %d", i)
		}
	}
	return round2Outputs, nil
}

func DoRound3(participants []*agreeonrandom.Participant, round2Inputs []network.RoundMessages[types.Protocol, *agreeonrandom.Round2Broadcast]) (results [][]byte, err error) {
	results = make([][]byte, len(participants))
	for i, participant := range participants {
		results[i], err = participant.Round3(round2Inputs[i])
		if err != nil {
			return nil, errs.WrapFailed(err, "could not execute round 3 for participant %d", i)
		}
	}
	return results, nil
}
