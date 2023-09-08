package test_utils

import "github.com/copperexchange/knox-primitives/pkg/threshold/dkg/pedersen/test_utils"

var (
	MakeDkgParticipants               = test_utils.MakeParticipants
	DoDkgRound1                       = test_utils.DoDkgRound1
	MapDkgRound1OutputsToRound2Inputs = test_utils.MapDkgRound1OutputsToRound2Inputs
	DoDkgRound2                       = test_utils.DoDkgRound2
)
