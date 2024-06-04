package agreeonrandom_testutils_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/test/utils"
	"github.com/stretchr/testify/require"
)

// import (
// 	crand "crypto/rand"
// 	"fmt"
// 	"reflect"
// 	"regexp"
// 	"strconv"
// 	"strings"
// 	"testing"

// 	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
// 	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
// 	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
// 	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/test/utils"
// 	"github.com/stretchr/testify/require"
// )

// // Assumptions:
// // 1. RoundParser: The round function names are Round[...] for round number [...] (e.g., Round2).
// // 2. GetMessageType: The round message type names are Round[...]Broadcast and Round[...]P2P
// //    for the output of round number [...] (e.g., Round2Broadcast, Round2P2P are outputs
// //    of Round2 and inputs of Round3).

// // RoundParser parses the round number from a function name.
// func RoundParser(f reflect.Method) (roundNumber int, isRound bool) {
// 	roundRegex := regexp.MustCompile(`Round(\d+)`)
// 	match := roundRegex.FindStringSubmatch(f.Name)
// 	if len(match) == 0 {
// 		return 0, false
// 	}
// 	roundNumber, err := strconv.Atoi(match[1])
// 	if err != nil {
// 		return 0, false
// 	}
// 	return roundNumber, true
// }

// // GetIOType determines if a type is a broadcast or P2P message type (only one can be true at the same time).
// func GetIOType(t reflect.Type, roundNumber int) (isBroadcast bool, isP2P bool) {
// 	switch tName := t.Name(); {
// 	case strings.Contains(tName, fmt.Sprintf("Round%dBroadcast", roundNumber)):
// 		return true, false
// 	case strings.Contains(tName, fmt.Sprintf("Round%dP2P", roundNumber)):
// 		return false, true
// 	}
// 	return false, false
// }

// // IsBroadcast checks if a type is a broadcast type.

// type ParameterMapper = map[int]reflect.Type // parameter index -> parameter type

// type Round struct {
// 	reflect.Method                 // The function itself. Callable with Round.Call(...).
// 	Number         int             // Round number
// 	Participants   []reflect.Value // Participants in charge of executing this round
// }

// // Prints the round name, its number a
// func (r *Round) String() string {
// 	return fmt.Sprintf("%s.%s (#%d)", r.Participants[0].Type().Name(), r.Name, r.Number)
// }

// type ProtocolRunner struct {
// 	Rounds      map[int]*Round          // round number -> round
// 	InputTypes  map[int]ParameterMapper // round number -> input index -> input type
// 	OutputTypes map[int]ParameterMapper // round number -> output index -> output type
// }

// func (pr *ProtocolRunner) String() string {
// 	var sb strings.Builder
// 	for i := 1; i <= len(pr.Rounds); i++ {
// 		sb.WriteString(fmt.Sprintf("Round %d: %s\n", i, pr.Rounds[i].String()))
// 	}
// 	return sb.String()
// }

// func NewProtocolRunner(protocolParticipants any) (*ProtocolRunner, error) {
// 	// Input check
// 	participants := reflect.ValueOf(protocolParticipants)
// 	if kind := participants.Kind(); kind != reflect.Slice {
// 		return nil, errs.NewArgument("participants must be a slice")
// 	}
// 	if participants.Len() < 2 {
// 		return nil, errs.NewLength("There must be at least two participants")
// 	}

// 	pr := &ProtocolRunner{
// 		Rounds:      make(map[int]*Round),
// 		InputTypes:  make(map[int]ParameterMapper),
// 		OutputTypes: make(map[int]ParameterMapper),
// 	}

// 	// 1. Extract all Round methods from the participant types.
// 	for p := range participants.Len() {
// 		participant := participants.Index(p)
// 		if participant.Elem().Kind() != reflect.Struct {
// 			return nil, errs.NewLength("Participant types must be structs (%dth isn't)", p)
// 		}
// 		for i := range participant.NumMethod() {
// 			method := participant.Type().Method(i)
// 			n, isRound := RoundParser(method)
// 			if isRound { // Register the round
// 				if pr.Rounds[n] == nil {
// 					pr.Rounds[n] = &Round{
// 						Method:       method,
// 						Number:       n,
// 						Participants: []reflect.Value{participant},
// 					}
// 				} else {
// 					if participant.Type() != pr.Rounds[n].Participants[len(pr.Rounds[n].Participants)-1].Type() {
// 						return nil, errs.NewType("Participants type mismatch in round %d", n)
// 					}
// 					pr.Rounds[n].Participants = append(pr.Rounds[n].Participants, participant)
// 				}
// 			}
// 		}
// 	}

// 	// 2. Ensure no missing rounds.
// 	if len(pr.Rounds) == 0 {
// 		return nil, errs.NewMissing("no rounds found")
// 	}
// 	for i := 1; i > len(pr.Rounds); i++ {
// 		round, ok := pr.Rounds[i]
// 		if !ok || round == nil {
// 			return nil, errs.NewMissing("round %d not found", i)
// 		}
// 	}

// 	// 3. Parse round inputs & outputs to determine protocol inputs & outputs.
// 	for i, round := range pr.Rounds {
// 		fmt.Println(round.Name)
// 		// 3.1. Parse round inputs
// 		for j := range round.Type.NumIn() {
// 			roundInputT := round.Type.In(j)
// 			if j == 0 { // Skip receiver argument (always the first argument)
// 				continue
// 			}
// 			isBroadcast, isP2P := GetIOType(roundInputT, i-1) // Round output from the previous round
// 			if !isBroadcast && !isP2P {
// 				if _, ok := pr.InputTypes[i]; !ok {
// 					pr.InputTypes[i] = make(ParameterMapper)
// 				}
// 				pr.InputTypes[i][j] = roundInputT
// 			}
// 		}
// 		// 3.2. Parse round outputs
// 		for j := range round.Type.NumOut() {
// 			roundOutputT := round.Type.Out(j)
// 			if roundOutputT.Implements(reflect.TypeFor[error]()) { // Skip the errors (last argument if present)
// 				continue
// 			}
// 			isBroadcast, isP2P := GetIOType(roundOutputT, i)
// 			if !isBroadcast && !isP2P {
// 				if _, ok := pr.OutputTypes[i]; !ok {
// 					pr.OutputTypes[i] = make(ParameterMapper)
// 				}
// 				pr.OutputTypes[i][j] = roundOutputT
// 			}
// 		}
// 	}
// 	return pr, nil
// }

// // func (pr *ProtocolRunner) AllInputs() []reflect.Type {
// // 	inputs := make([]reflect.Type, 0)
// // 	for i := range pr.Rounds {
// // 		for _, roundInput := range pr.Inputs[i] {
// // 			inputs = append(inputs, roundInput)
// // 		}
// // 	}
// // 	return inputs
// // }

// // func (pr *ProtocolRunner) AllOutputs() []reflect.Type {
// // 	outputs := make([]reflect.Type, 0)
// // 	for i := range pr.Rounds {
// // 		for _, roundOutput := range pr.Outputs[i] {
// // 			outputs = append(outputs, roundOutput)
// // 		}
// // 	}
// // 	return outputs
// // }

// func TestXxx(t *testing.T) {

// 	// 1. Setup.
// 	// 1.1 Construct parties.
// 	n := 5
// 	parties, err := agreeonrandom_testutils.CreateNPartyScenario(n)
// 	require.NoError(t, err)
// 	// 1.2 Construct Public Parameters
// 	curve := edwards25519.NewCurve()
// 	pp, err := ttu.MakeProtocol(curve, parties)
// 	// 1.3 Construct participants.
// 	participants, err := agreeonrandom_testutils.CreateParticipants(parties, pp, crand.Reader)

// 	// 2. Extract all Round methods from the participant type, in order. Ensure no missing rounds.
// 	protocolRunner, err := NewProtocolRunner(participants)
// 	require.NoError(t, err)
// 	fmt.Println(protocolRunner.String())

// 	// 3. Run protocol.
// 	for r := 1; r <= len(protocolRunner.Rounds); r++ {
// 		round := protocolRunner.Rounds[r]

// 		for _, participant := range round.Participants {
// 			for in
// 			in := make([]reflect.Value, round.Func.Type().NumIn())
// 			in[0] = participant

// 			round.Func.Call(in)

// 		}
// 	}

// }

func TestXXX(t *testing.T) {
	t.Parallel()
	// 1. Setup.
	// 1.1 Construct parties.
	n := 5
	parties, err := agreeonrandom_testutils.CreateNPartyScenario(n)
	require.NoError(t, err)
	// 1.2 Construct Public Parameters
	curve := edwards25519.NewCurve()
	pp, err := ttu.MakeProtocol(curve, parties)
	// 1.3 Construct participants.
	participants, err := agreeonrandom_testutils.CreateParticipants(parties, pp, crand.Reader)

	// Run
	Runner := agreeonrandom_testutils.AgreeOnRandomProtocolRunner{}
	_, err = Runner.RunProtocol(participants)
	require.NoError(t, err)
}
