package test_utils

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/dkg/pedersen/test_utils"
)

var MakeDkgParticipants = test_utils.MakeParticipants
var DoDkgRound1 = test_utils.DoDkgRound1
var MapDkgRound1OutputsToRound2Inputs = test_utils.MapDkgRound1OutputsToRound2Inputs
var DoDkgRound2 = test_utils.DoDkgRound2
var MapDkgRound2OutputsToRound3Inputs = test_utils.MapDkgRound2OutputsToRound3Inputs
var DoDkgRound3 = test_utils.DoDkgRound3
